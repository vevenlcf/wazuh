# Copyright (C) 2015-2019, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GP

import copy
import fcntl
import hashlib
import ipaddress
import socket
from base64 import b64encode
from datetime import date, datetime, timedelta, timezone
from glob import glob
from os import chown, chmod, path, makedirs, urandom, stat, remove
from platform import platform
from shutil import copyfile, rmtree
from time import time, sleep

import requests

from wazuh import configuration
from wazuh.core import common
from wazuh.InputValidator import InputValidator
from wazuh.core.cluster.utils import get_manager_status
from wazuh.database import Connection
from wazuh.exception import WazuhException, WazuhError, WazuhInternalError
from wazuh.ossec_queue import OssecQueue
from wazuh.ossec_socket import OssecSocket, OssecSocketJSON
from wazuh.utils import chmod_r, WazuhVersion, plain_dict_to_nested_dict, get_fields_to_nest, WazuhDBQuery, \
    WazuhDBQueryDistinct, WazuhDBQueryGroupBy, SQLiteBackend, WazuhDBBackend, safe_move


class WazuhDBQueryAgents(WazuhDBQuery):

    def __init__(self, offset=0, limit=common.database_limit, sort=None, search=None, select=None, count=True,
                 get_data=True, query='', filters=None, default_sort_field='id', min_select_fields=None,
                 remove_extra_fields=True, distinct=False):
        if filters is None:
            filters = {}
        if min_select_fields is None:
            min_select_fields = {'lastKeepAlive', 'version', 'id'}
        backend = SQLiteBackend(common.database_path_global)
        WazuhDBQuery.__init__(self, offset=offset, limit=limit, table='agent', sort=sort, search=search, select=select,
                              filters=filters, fields=Agent.fields, default_sort_field=default_sort_field,
                              default_sort_order='ASC', query=query, backend=backend,
                              min_select_fields=min_select_fields, count=count, get_data=get_data,
                              date_fields={'lastKeepAlive', 'dateAdd'}, extra_fields={'internal_key'}, distinct=distinct)
        self.remove_extra_fields = remove_extra_fields

    def _filter_status(self, status_filter):
        # set the status value to lowercase in case it's a string. If not, the value will be return unmodified.
        status_filter['value'] = getattr(status_filter['value'], 'lower', lambda: status_filter['value'])()
        result = datetime.utcnow() - timedelta(seconds=common.limit_seconds)
        self.request['time_active'] = result.replace(tzinfo=timezone.utc).timestamp()
        if status_filter['operator'] == '!=':
            self.query += ' NOT '

        if status_filter['value'] == 'active':
            self.query += '(last_keepalive >= :time_active AND version IS NOT NULL) or id = 0'
        elif status_filter['value'] == 'disconnected':
            self.query += 'last_keepalive < :time_active'
        elif status_filter['value'] == "never_connected":
            self.query += 'last_keepalive IS NULL AND id != 0'
        elif status_filter['value'] == 'pending':
            self.query += 'last_keepalive IS NOT NULL AND version IS NULL'
        else:
            raise WazuhError(1729, extra_message=status_filter['value'])

    def _filter_date(self, date_filter, filter_db_name):
        WazuhDBQuery._filter_date(self, date_filter, filter_db_name)
        self.query = self.query[:-1] + ' AND id != 0'

    def _sort_query(self, field):
        if field == 'status':
            # Order by status ASC is the same that order by last_keepalive DESC.
            return '{} {}'.format('last_keepAlive', self.sort['order'])
        elif field == 'os.version':
            return "CAST(os_major AS INTEGER) {0}, CAST(os_minor AS INTEGER) {0}".format(self.sort['order'])
        else:
            return WazuhDBQuery._sort_query(self, field)

    def _add_search_to_query(self):
        # since id are stored in database as integers, id searches must be turned into integers to work as expected.
        if self.search:
            del self.fields['id']
            WazuhDBQuery._add_search_to_query(self)
            self.fields['id'] = 'id'
            self.query = self.query[:-1] + ' OR id LIKE :search_id)'
            self.request['search_id'] = int(self.search['value']) if self.search['value'].isdigit() \
                else self.search['value']

    def _format_data_into_dictionary(self):
        fields_to_nest, non_nested = get_fields_to_nest(self.fields.keys(), ['os'], '.')

        today = datetime.utcnow()

        # compute 'status' field, format id with zero padding and remove non-user-requested fields.
        # Also remove, extra fields (internal key and registration IP)
        selected_fields = self.select - self.extra_fields if self.remove_extra_fields else self.select
        selected_fields |= {'id'}
        self._data = [{key: format_fields(key, value, today, item.get('lastKeepAlive'), item.get('version'))
                      for key, value in item.items() if key in selected_fields} for item in self._data]

        self._data = [plain_dict_to_nested_dict(d, fields_to_nest, non_nested, ['os'], '.') for d in self._data]

        return super()._format_data_into_dictionary()

    def _parse_legacy_filters(self):
        if 'older_than' in self.legacy_filters:
            if self.legacy_filters['older_than']:
                self.q = (self.q + ';' if self.q else '') + \
                          "(lastKeepAlive>{0};status!=never_connected,dateAdd>{0};status=never_connected)".format(
                              self.legacy_filters['older_than'])
            del self.legacy_filters['older_than']
        WazuhDBQuery._parse_legacy_filters(self)

    def _process_filter(self, field_name, field_filter, q_filter):
        if field_name == 'group' and q_filter['value'] is not None:
            field_filter_1, field_filter_2, field_filter_3 = \
                field_filter + '_1', field_filter + '_2', field_filter + '_3'
            self.query += '{0} LIKE :{1} OR {0} LIKE :{2} OR {0} LIKE :{3} OR {0} = :{4}'.format(
                self.fields[field_name], field_filter_1, field_filter_2, field_filter_3, field_filter)
            self.request[field_filter_1] = '%,' + q_filter['value']
            self.request[field_filter_2] = q_filter['value'] + ',%'
            self.request[field_filter_3] = '%,{},%'.format(q_filter['value'])
            self.request[field_filter] = q_filter['value']
        else:
            WazuhDBQuery._process_filter(self, field_name, field_filter, q_filter)


class WazuhDBQueryGroup(WazuhDBQuery):
    def __init__(self, offset=0, limit=common.database_limit, sort=None, search=None, select=None, count=True,
                 get_data=True, query='', filters=None, default_sort_field='id', min_select_fields=None,
                 remove_extra_fields=True):
        if filters is None:
            filters = {}
        if min_select_fields is None:
            min_select_fields = {'id'}
        backend = SQLiteBackend(common.database_path_global)
        WazuhDBQuery.__init__(self, offset=offset, limit=limit, table='`group`', sort=sort, search=search, select=select,
                              filters=filters, fields={'id': 'id', 'name': 'name'},
                              default_sort_field=default_sort_field, default_sort_order='ASC', query=query,
                              backend=backend, min_select_fields=min_select_fields, count=count, get_data=get_data)
        self.remove_extra_fields = remove_extra_fields


class WazuhDBQueryDistinctAgents(WazuhDBQueryDistinct, WazuhDBQueryAgents):
    pass


class WazuhDBQueryGroupByAgents(WazuhDBQueryGroupBy, WazuhDBQueryAgents):
    def __init__(self, filter_fields, *args, **kwargs):
        self.real_fields = copy.deepcopy(filter_fields)

        if filter_fields is not None:
            if 'status' in filter_fields:
                if 'lastKeepAlive' not in filter_fields:
                    filter_fields.append('lastKeepAlive')
                if 'version' not in filter_fields:
                    filter_fields.append('version')

        WazuhDBQueryAgents.__init__(self, *args, **kwargs)
        WazuhDBQueryGroupBy.__init__(self, *args, table=self.table, fields=self.fields, filter_fields=filter_fields,
                                     default_sort_field=self.default_sort_field, backend=self.backend, **kwargs)
        self.remove_extra_fields = True

    def _format_data_into_dictionary(self):
        # Add <field>: 'unknown' when filter field is not within the response.
        if not self.real_fields or self.filter_fields == {'fields': set(self.real_fields)}:
            for result in self._data:
                for field in self.filter_fields['fields']:
                    if field not in result.keys():
                        result[field] = 'unknown'
            return super()._format_data_into_dictionary()
        else:
            fields_to_nest, non_nested = get_fields_to_nest(self.fields.keys(), ['os'], '.')

            today = datetime.utcnow()

            # compute 'status' field, format id with zero padding and remove non-user-requested fields.
            # Also remove, extra fields (internal key and registration IP)
            selected_fields = self.select - self.extra_fields if self.remove_extra_fields else self.select
            selected_fields |= {'id'}
            self._data = [{key: format_fields(key, value, today, item.get('lastKeepAlive'), item.get('version'))
                           for key, value in item.items() if key in selected_fields} for item in self._data]

            # Create tuples like ({values in self.real_fields}, count) in order to keep the 'count' field and discard
            # the values not requested by the user.
            tuples_list = [({k: result[k] if k in result.keys() else 'unknown' for k in self.real_fields},
                            result['count']) for result in self._data]

            # Sum the 'count' value of all the dictionaries that are equal
            result_list = list()
            added_dicts = list()
            for i, i_tuple in enumerate(tuples_list):
                if i not in added_dicts:
                    for j, j_tuple in enumerate(tuples_list):
                        if j_tuple[0] == i_tuple[0] and j > i:
                            tuples_list[i] = (tuples_list[i][0], tuples_list[i][1] + tuples_list[j][1])
                            added_dicts.append(j)
                    result_list.append(tuples_list[i])

            # Append 'count' value in each dict
            self._data = []
            for dikt in result_list:
                dikt[0].update({'count': dikt[1]})
                self._data.append(dikt[0])

            self._data = [plain_dict_to_nested_dict(d, fields_to_nest, non_nested, ['os'], '.') for d in self._data]

            return WazuhDBQuery._format_data_into_dictionary(self)


class WazuhDBQueryMultigroups(WazuhDBQueryAgents):
    def __init__(self, group_id, query='', *args, **kwargs):
        self.group_id = group_id
        query = 'group={}'.format(group_id) + (';'+query if query else '')
        WazuhDBQueryAgents.__init__(self, query=query, *args, **kwargs)

    def _default_query(self):
        return "SELECT {0} FROM agent a LEFT JOIN belongs b ON a.id = b.id_agent" if self.group_id != "null" \
                                                                                  else "SELECT {0} FROM agent a"

    def _default_count_query(self):
        return 'COUNT(DISTINCT a.id)'

    def _get_total_items(self):
        self.total_items = self.backend.execute(self.query.format(self._default_count_query()), self.request, True)
        self.query += ' GROUP BY a.id '


class Agent:
    """OSSEC Agent object.
    """
    fields = {'id': 'id', 'name': 'name', 'ip': 'coalesce(ip,register_ip)', 'status': 'status',
              'os.name': 'os_name', 'os.version': 'os_version', 'os.platform': 'os_platform',
              'version': 'version', 'manager': 'manager_host', 'dateAdd': 'date_add',
              'group': '`group`', 'mergedSum': 'merged_sum', 'configSum': 'config_sum',
              'os.codename': 'os_codename', 'os.major': 'os_major', 'os.minor': 'os_minor',
              'os.uname': 'os_uname', 'os.arch': 'os_arch', 'os.build': 'os_build',
              'node_name': 'node_name', 'lastKeepAlive': 'last_keepalive', 'internal_key': 'internal_key',
              'registerIP': 'register_ip'}

    def __init__(self, id=None, name=None, ip=None, key=None, force=-1, use_only_authd=False):
        """Initialize an agent.

        :param: id: When the agent exists
        :param: name and ip: Add an agent (generate id and key automatically)
        :param: name, ip and force: Add an agent (generate id and key automatically), removing old agent with same IP if
        disconnected since <force> seconds.
        :param: name, ip, id, key: Insert an agent with an existent id and key
        :param: name, ip, id, key, force: Insert an agent with an existent id and key, removing old agent with same IP
         if disconnected since <force> seconds.
        """
        self.id = id
        self.name = name
        self.ip = ip
        self.internal_key = key
        self.os = {}
        self.version = None
        self.dateAdd = None
        self.lastKeepAlive = None
        self.status = None
        self.key = None
        self.configSum = None
        self.mergedSum = None
        self.group = None
        self.manager = None
        self.node_name = None
        self.registerIP = ip

        # if the method has only been called with an ID parameter, no new agent should be added.
        # Otherwise, a new agent must be added
        if name is not None and ip is not None:
            self._add(name=name, ip=ip, id=id, key=key, force=force, use_only_authd=use_only_authd)

    def __str__(self):
        return str(self.to_dict())

    def to_dict(self):
        dictionary = {'id': self.id, 'name': self.name, 'ip': self.ip, 'internal_key': self.internal_key, 'os': self.os,
                      'version': self.version, 'dateAdd': self.dateAdd, 'lastKeepAlive': self.lastKeepAlive,
                      'status': self.status, 'key': self.key, 'configSum': self.configSum, 'mergedSum': self.mergedSum,
                      'group': self.group, 'manager': self.manager, 'node_name': self.node_name}

        return dictionary

    def load_info_from_db(self, select=None):
        """Gets attributes of existing agent.
        """
        db_query = WazuhDBQueryAgents(offset=0, limit=None, sort=None, search=None, select=select,
                                      query="id={}".format(self.id), count=False, get_data=True,
                                      remove_extra_fields=False)
        try:
            data = db_query.run()['items'][0]
        except IndexError:
            raise WazuhError(1701)

        list(map(lambda x: setattr(self, x[0], x[1]), data.items()))

    def get_basic_information(self, select=None):
        """Gets public attributes of existing agent.
        """
        self.load_info_from_db(select)
        fields = set(self.fields.keys()) & set(select) if select is not None \
            else set(self.fields.keys()) - {'internal_key'}
        return {field: getattr(self, field) for field in map(lambda x: x.split('.')[0], fields) if getattr(self, field)}

    def compute_key(self):
        str_key = "{0} {1} {2} {3}".format(self.id, self.name, self.registerIP, self.internal_key)
        return b64encode(str_key.encode()).decode()

    def get_key(self):
        """Gets agent key.

        :return: Agent key.
        """
        self.load_info_from_db()
        if self.id != "000":
            self.key = self.compute_key()
        else:
            raise WazuhError(1703)

        return self.key

    def restart(self):
        """Restarts the agent.

        :return: Message generated by OSSEC.
        """
        # Check if agent is active
        self.get_basic_information()
        if self.status.lower() != 'active':
            raise WazuhError(1707, extra_message='{0}'.format(self.status))

        # Check if agent has active-response enabled
        agent_conf = self.getconfig('com', 'active-response')
        if agent_conf['active-response']['disabled'] == 'yes':
            raise WazuhException(1750)

        return send_restart_command(self.id)

    def remove(self, backup=False, purge=False, use_only_authd=False):
        """Deletes the agent.

        :param backup: Create backup before removing the agent.
        :param purge: Delete definitely from key store.
        :param use_only_authd: Force the use of authd when adding and removing agents.
        :return: Message.
        """

        manager_status = get_manager_status()
        is_authd_running = 'ossec-authd' in manager_status and manager_status['ossec-authd'] == 'running'

        if use_only_authd:
            if not is_authd_running:
                raise WazuhInternalError(1726)

        if not is_authd_running:
            data = self._remove_manual(backup, purge)
        else:
            data = self._remove_authd(purge)

        return data

    def _remove_authd(self, purge=False):
        """Deletes the agent.

        :param purge: Delete definitely from key store.
        :return: Message.
        """
        msg = {"function": "remove", "arguments": {"id": str(self.id).zfill(3), "purge": purge}}

        authd_socket = OssecSocketJSON(common.AUTHD_SOCKET)
        authd_socket.send(msg)
        data = authd_socket.receive()
        authd_socket.close()

        return data

    def _remove_manual(self, backup=False, purge=False):
        """Deletes the agent.

        :param backup: Create backup before removing the agent.
        :param purge: Delete definitely from key store.
        :return: Message.
        """
        # Check if agent exists
        self.load_info_from_db()

        f_keys_temp = '{0}.tmp'.format(common.client_keys)

        try:
            agent_found = False
            with open(common.client_keys) as client_keys, open(f_keys_temp, 'w') as client_keys_tmp:
                try:
                    for line in client_keys.readlines():
                        id, name, ip, key = line.strip().split(' ')  # 0 -> id, 1 -> name, 2 -> ip, 3 -> key
                        if self.id == id and name[0] not in '#!':
                            if not purge:
                                client_keys_tmp.write('{0} !{1} {2} {3}\n'.format(id, name, ip, key))

                            agent_found = True
                        else:
                            client_keys_tmp.write(line)
                except Exception as e:
                    remove(f_keys_temp)
                    raise e

            if not agent_found:
                remove(f_keys_temp)
                raise WazuhError(1701, extra_message=str(self.id))
            else:
                f_keys_st = stat(common.client_keys)
                chown(f_keys_temp, common.ossec_uid(), common.ossec_gid())
                chmod(f_keys_temp, f_keys_st.st_mode)
        except Exception as e:
            raise WazuhInternalError(1746, extra_message=str(e))

        # Tell wazuhbd to delete agent database
        wdb_conn = WazuhDBBackend(self.id).connect_to_db()
        wdb_conn.delete_agents_db([self.id])

        try:
            # remove agent from groups
            db_global = glob(common.database_path_global)
            if not db_global:
                raise WazuhError(1600)

            conn = Connection(db_global[0])
            conn.execute('DELETE FROM belongs WHERE id_agent = :id_agent', {'id_agent': int(self.id)})
            conn.commit()
        except Exception as e:
            raise WazuhInternalError(1747, extra_message=str(e))

        try:
            # Remove rid file
            rids_file = path.join(common.ossec_path, 'queue/rids', self.id)
            if path.exists(rids_file):
                remove(rids_file)

            if backup:
                # Create backup directory
                # /var/ossec/backup/agents/yyyy/Mon/dd/id-name-ip[tag]
                date_part = date.today().strftime('%Y/%b/%d')
                main_agent_backup_dir = path.join(common.backup_path,
                                                  f'agents/{date_part}/{self.id}-{self.name}-{self.registerIP}')
                agent_backup_dir = main_agent_backup_dir

                not_agent_dir = True
                i = 0
                while not_agent_dir:
                    if path.exists(agent_backup_dir):
                        i += 1
                        agent_backup_dir = '{0}-{1}'.format(main_agent_backup_dir, str(i).zfill(3))
                    else:
                        makedirs(agent_backup_dir)
                        chmod_r(agent_backup_dir, 0o750)
                        not_agent_dir = False
            else:
                agent_backup_dir = ''

            # Move agent file
            agent_files = [
                ('{0}/queue/agent-info/{1}-{2}'.format(common.ossec_path, self.name, self.registerIP),
                 '{0}/agent-info'.format(agent_backup_dir)),
                ('{0}/queue/rootcheck/({1}) {2}->rootcheck'.format(common.ossec_path, self.name, self.registerIP),
                 '{0}/rootcheck'.format(agent_backup_dir)),
                ('{0}/queue/agent-groups/{1}'.format(common.ossec_path, self.id),
                 '{0}/agent-group'.format(agent_backup_dir)),
                ('{}/var/db/agents/{}-{}.db'.format(common.ossec_path, self.name, self.id),
                 '{}/var_db'.format(agent_backup_dir)),
                ('{}/queue/diff/{}'.format(common.ossec_path, self.name), '{}/diff'.format(agent_backup_dir))
            ]

            for agent_file, backup_file in agent_files:
                if path.exists(agent_file):
                    if not backup:
                        if path.isdir(agent_file):
                            rmtree(agent_file)
                        else:
                            remove(agent_file)
                    elif not path.exists(backup_file):
                        safe_move(agent_file, backup_file, permissions=0o660)

            # Overwrite client.keys
            safe_move(f_keys_temp, common.client_keys, permissions=0o640)
        except Exception as e:
            raise WazuhInternalError(1748, extra_message=str(e))

        return 'Agent deleted successfully.'

    def _add(self, name, ip, id=None, key=None, force=-1, use_only_authd=False):
        """Adds an agent to OSSEC.
        2 uses:
            - name and ip [force]: Add an agent like manage_agents (generate id and key).
            - name, ip, id, key [force]: Insert an agent with an existing id and key.

        :param name: name of the new agent.
        :param ip: IP of the new agent. It can be an IP, IP/NET or ANY.
        :param id: ID of the new agent.
        :param key: Key of the new agent.
        :param force: Remove old agents with same IP if disconnected since <force> seconds
        :param use_only_authd: Force the use of authd when adding and removing agents.
        :return: Agent ID.
        """
        ip = ip.lower()
        if ip != 'any':
            if ip.find('/') > 0:
                try:
                    ipaddress.ip_network(ip)
                except Exception:
                    raise WazuhError(1706, extra_message=ip)
            else:
                try:
                    ipaddress.ip_address(ip)
                except Exception:
                    raise WazuhError(1706, extra_message=ip)

        manager_status = get_manager_status()
        is_authd_running = 'ossec-authd' in manager_status and manager_status['ossec-authd'] == 'running'

        if use_only_authd:
            if not is_authd_running:
                raise WazuhInternalError(1726)

        if not is_authd_running:
            data = self._add_manual(name, ip, id, key, force)
        else:
            data = self._add_authd(name, ip, id, key, force)

        return data

    def _add_authd(self, name, ip, id=None, key=None, force=-1):
        """Adds an agent to OSSEC using authd.
        2 uses:
            - name and ip [force]: Add an agent like manage_agents (generate id and key).
            - name, ip, id, key [force]: Insert an agent with an existing id and key.

        :param name: name of the new agent.
        :param ip: IP of the new agent. It can be an IP, IP/NET or ANY.
        :param id: ID of the new agent.
        :param key: Key of the new agent.
        :param force: Remove old agents with same IP if disconnected since <force> seconds
        :return: Agent ID.
        """
        # Check arguments
        if id:
            id = id.zfill(3)

        if key and len(key) < 64:
            raise WazuhError(1709)

        force = force if type(force) == int else int(force)

        msg = ""
        if name and ip:
            if id and key:
                msg = {"function": "add", "arguments": {"name": name, "ip": ip, "id": id, "key": key, "force": force}}
            else:
                msg = {"function": "add", "arguments": {"name": name, "ip": ip, "force": force}}

        try:
            authd_socket = OssecSocketJSON(common.AUTHD_SOCKET)
            authd_socket.send(msg)
            data = authd_socket.receive()
            authd_socket.close()
        except WazuhError as e:
            if e.code == 9008:
                raise WazuhError(1705, extra_message=name)
            elif e.code == 9007:
                raise WazuhError(1706, extra_message=ip)
            elif e.code == 9012:
                raise WazuhError(1708, extra_message=id)
            raise e

        self.id = data['id']
        self.internal_key = data['key']
        self.key = self.compute_key()

    def _add_manual(self, name, ip, id=None, key=None, force=-1):
        """Adds an agent to OSSEC manually.
        2 uses:
            - name and ip [force]: Add an agent like manage_agents (generate id and key).
            - name, ip, id, key [force]: Insert an agent with an existing id and key.

        :param name: name of the new agent.
        :param ip: IP of the new agent. It can be an IP, IP/NET or ANY.
        :param id: ID of the new agent.
        :param key: Key of the new agent.
        :param force: Remove old agents with same IP if disconnected since <force> seconds
        :return: Agent ID.
        """
        # Check arguments
        if id:
            id = id.zfill(3)

        if key and len(key) < 64:
            raise WazuhError(1709)

        force = force if type(force) == int else int(force)

        # Check manager name
        db_global = glob(common.database_path_global)
        if not db_global:
            raise WazuhInternalError(1600)

        conn = Connection(db_global[0])
        conn.execute("SELECT name FROM agent WHERE (id = 0)")
        manager_name = str(conn.fetch())

        if name == manager_name:
            raise WazuhError(1705, extra_message=name)

        # Check if ip, name or id exist in client.keys
        last_id = 0
        lock_file = open("{}/var/run/.api_lock".format(common.ossec_path), 'a+')
        fcntl.lockf(lock_file, fcntl.LOCK_EX)
        with open(common.client_keys) as f_k:
            try:
                for line in f_k.readlines():
                    if not line.strip():  # ignore empty lines
                        continue

                    if line[0] in '# ':  # starts with # or ' '
                        continue

                    line_data = line.strip().split(' ')  # 0 -> id, 1 -> name, 2 -> ip, 3 -> key

                    line_id = int(line_data[0])
                    if last_id < line_id:
                        last_id = line_id

                    if line_data[1][0] in '#!':  # name starts with # or !
                        continue

                    check_remove = 0
                    if id and id == line_data[0]:
                        raise WazuhError(1708, extra_message=id)
                    if name == line_data[1]:
                        if force < 0:
                            raise WazuhError(1705, extra_message=name)
                        else:
                            check_remove = 1
                    if ip != 'any' and ip == line_data[2]:
                        if force < 0:
                            raise WazuhError(1706, extra_message=ip)
                        else:
                            check_remove = 2

                    if check_remove:
                        if force == 0 or Agent.check_if_delete_agent(line_data[0], force):
                            Agent(line_data[0]).remove(backup=True)
                        else:
                            if check_remove == 1:
                                raise WazuhError(1705, extra_message=name)
                            else:
                                raise WazuhError(1706, extra_message=ip)

                if not id:
                    agent_id = str(last_id + 1).zfill(3)
                else:
                    agent_id = id

                if not key:
                    # Generate key
                    epoch_time = int(time())
                    str1 = "{0}{1}{2}".format(epoch_time, name, platform())
                    str2 = "{0}{1}".format(ip, agent_id)
                    hash1 = hashlib.md5(str1.encode())
                    hash1.update(urandom(64))
                    hash2 = hashlib.md5(str2.encode())
                    hash1.update(urandom(64))
                    agent_key = hash1.hexdigest() + hash2.hexdigest()
                else:
                    agent_key = key

                # Tmp file
                f_keys_temp = '{0}.tmp'.format(common.client_keys)
                open(f_keys_temp, 'a').close()

                f_keys_st = stat(common.client_keys)
                chown(f_keys_temp, common.ossec_uid(), common.ossec_gid())
                chmod(f_keys_temp, f_keys_st.st_mode)

                copyfile(common.client_keys, f_keys_temp)

                # Write key
                with open(f_keys_temp, 'a') as f_kt:
                    f_kt.write('{0} {1} {2} {3}\n'.format(agent_id, name, ip, agent_key))

                # Overwrite client.keys
                safe_move(f_keys_temp, common.client_keys, permissions=f_keys_st.st_mode)
            except WazuhException as ex:
                fcntl.lockf(lock_file, fcntl.LOCK_UN)
                lock_file.close()
                raise ex
            except Exception as e:
                fcntl.lockf(lock_file, fcntl.LOCK_UN)
                lock_file.close()
                raise WazuhError(1725, extra_message=str(e))

            fcntl.lockf(lock_file, fcntl.LOCK_UN)
            lock_file.close()

        self.id = agent_id
        self.internal_key = agent_key
        self.key = self.compute_key()

    @staticmethod
    def delete_single_group(group_id):
        """Delete a group

        :param group_id: Group ID.
        :return: Confirmation message.
        """
        # Delete group directory (move it to a backup)
        group_path = path.join(common.shared_path, group_id)
        group_backup = path.join(common.backup_path, 'groups', "{0}_{1}".format(group_id, int(time())))
        if path.exists(group_path):
            safe_move(group_path, group_backup, permissions=0o660)

        msg = "Group '{0}' deleted.".format(group_id)

        return {'message': msg}

    def get_agent_attr(self, attr):
        """Returns a string with an agent's os name
        """
        db_global = glob(common.database_path_global)
        if not db_global:
            raise WazuhInternalError(1600)

        conn = Connection(db_global[0])
        query = "SELECT {0} FROM agent WHERE id = {1}".format(attr, self.id)
        request = {'attr': attr, 'id': self.id}
        conn.execute(query, request)
        query_value = str(conn.fetch())

        return query_value

    @staticmethod
    def get_agents_overview(offset=0, limit=common.database_limit, sort=None, search=None, select=None,
                            filters=None, q=""):
        """Gets a list of available agents with basic attributes.

        :param offset: First item to return.
        :param limit: Maximum number of items to return.
        :param sort: Sorts the items. Format: {"fields":["field1","field2"],"order":"asc|desc"}.
        :param select: Select fields to return. Format: {"fields":["field1","field2"]}.
        :param search: Looks for items with the specified string. Format: {"fields": ["field1","field2"]}
        :param filters: Defines required field filters.
        Format: {"field1":"value1", "field2":["value2","value3"]}
        :param q: Defines query to filter in DB.
        :return: Dictionary: {'items': array of items, 'totalItems': Number of items (without applying the limit)}
        """
        db_query = WazuhDBQueryAgents(offset=offset, limit=limit, sort=sort, search=search, select=select,
                                      filters=filters, query=q)
        data = db_query.run()

        return data

    @staticmethod
    def add_group_to_agent(group_id, agent_id, force=False, replace=False, replace_list=None):
        """Adds an existing group to an agent

        :param group_id: name of the group.
        :param agent_id: ID of the agent.
        :param force: Do not check if agent exists
        :param replace: Whether to append new group to current agent's group or replace it.
        :param replace_list: List of Group names that can be replaced
        :return: Agent ID.
        """
        if replace_list is None:
            replace_list = []
        if not force:
            # Check if agent exists, it is not 000 and the group exists
            Agent(agent_id).get_basic_information()

            if agent_id == "000":
                raise WazuhError(1703)

            if not Agent.group_exists(group_id):
                raise WazuhError(1710)

        # Get agent's group
        group_path = path.join(common.groups_path, agent_id)
        try:
            with open(group_path) as f:
                multigroup_name = f.read().replace('\n', '')
        except Exception as e:
            # Check if agent is never_connected.
            failed = Agent(agent_id)
            failed.load_info_from_db()
            if failed.status == 'never_connected':
                raise WazuhError(1753)
            raise WazuhInternalError(1005, extra_message=str(e))
        agent_groups = set(multigroup_name.split(','))

        if replace:
            if agent_groups.issubset(set(replace_list)):
                multigroup_name = group_id
            else:
                raise WazuhError(1752)
        else:
            # Check if the group already belongs to the agent
            if group_id in multigroup_name.split(','):
                raise WazuhError(1751)

            multigroup_name = (multigroup_name + ',' if multigroup_name else '') + group_id

        # Check multigroup limit
        if Agent.check_multigroup_limit(agent_id):
            raise WazuhError(1737)

        # Update group file
        Agent.set_agent_group_file(agent_id, multigroup_name)

        return f"Agent {agent_id} assigned to {group_id}"

    @staticmethod
    def check_if_delete_agent(id, seconds):
        """Check if we should remove an agent: if time from last connection is greater thant <seconds>.

        :param id: id of the new agent.
        :param seconds: Number of seconds.
        :return: True if time from last connection is greater thant <seconds>.
        """
        remove_agent = False
        agent_info = Agent(id=id).get_basic_information()

        if 'lastKeepAlive' in agent_info:
            if agent_info['lastKeepAlive'] == 0:
                remove_agent = True
            else:
                if isinstance(agent_info['lastKeepAlive'], datetime):
                    last_date = agent_info['lastKeepAlive']
                else:
                    last_date = datetime.strptime(agent_info['lastKeepAlive'], '%Y-%m-%d %H:%M:%S')
                difference = (datetime.utcnow() - last_date).total_seconds()
                if difference >= seconds:
                    remove_agent = True

        return remove_agent


    @staticmethod
    def group_exists(group_id):
        """Checks if the group exists

        :param group_id: Group ID.
        :return: True if group exists, False otherwise
        """
        # Input Validation of group_id
        if not InputValidator().group(group_id):
            raise WazuhError(1722)

        if path.exists(path.join(common.shared_path, group_id)):
            return True
        else:
            return False


    @staticmethod
    def get_agents_group_file(agent_id):
        group_path = path.join(common.groups_path, agent_id)
        if path.exists(group_path):
            with open(group_path) as f:
                group_name = f.read().strip()
            return group_name
        else:
            return ''

    @staticmethod
    def set_agent_group_file(agent_id, group_id):
        try:
            agent_group_path = path.join(common.groups_path, agent_id)
            new_file = not path.exists(agent_group_path)

            with open(agent_group_path, 'w') as f_group:
                f_group.write(group_id)

            if new_file:
                chown(agent_group_path, common.ossec_uid(), common.ossec_gid())
                chmod(agent_group_path, 0o660)
        except Exception as e:
            raise WazuhInternalError(1005, extra_message=str(e))


    @staticmethod
    def check_multigroup_limit(agent_id):
        """An agent can belong to <common.max_groups_per_multigroup> groups as maximum. This function checks
        that limit is not yet reached.

        :param agent_id: Agent ID to check
        :return: True if the limit is reached, False otherwise
        """
        group_read = Agent.get_agents_group_file(agent_id)
        if group_read:
            return len(group_read.split(',')) >= common.max_groups_per_multigroup
        else:
            # In case that the agent is not connected and has no assigned group, the file is not created.
            # So, the limit is not reached.
            return False

    @staticmethod
    def unset_single_group_agent(agent_id, group_id, force=False):
        """Unset the agent group. If agent has multigroups, it will preserve all previous groups except the last one.

        :param agent_id: Agent ID.
        :param group_id: Group ID.
        :param force: Do not check if agent or group exists
        :return: Confirmation message.
        """
        if not force:
            # Check if agent exists, it is not 000 and the group exists
            Agent(agent_id).get_basic_information()

            if agent_id == "000":
                raise WazuhError(1703)

            if not Agent.group_exists(group_id):
                raise WazuhError(1710)

        # Get agent's group
        group_name = Agent.get_agents_group_file(agent_id)
        group_list = group_name.split(',')
        # Check agent belongs to group group_id
        if group_id not in group_list:
            raise WazuhError(1734)
        elif group_id == 'default' and len(group_list) == 1:
            raise WazuhError(1745)
        # Remove group from group_list
        group_list.remove(group_id)
        set_default = False
        if len(group_list) > 1:
            multigroup_name = ','.join(group_list)
        elif not group_list:
            set_default = True
            multigroup_name = 'default'
        else:
            multigroup_name = group_list[0]
        # Update group file
        Agent.set_agent_group_file(agent_id, multigroup_name)

        return f"Agent '{agent_id}' removed from '{group_id}'." + (" Agent reassigned to group default."
                                                                   if set_default else "")

    @staticmethod
    def _get_protocol(wpk_repo, use_http=False):
        protocol = ""
        if "http://" not in wpk_repo and "https://" not in wpk_repo:
            protocol = "https://" if not use_http else "http://"

        return protocol

    def _get_versions(self, wpk_repo=common.wpk_repo_url, version=None, use_http=False):
        """Generates a list of available versions for its distribution and version.
        """
        invalid_platforms = ["darwin", "solaris", "aix", "hpux", "bsd"]
        not_valid_versions = [("sles", 11), ("rhel", 5), ("centos", 5)]

        if self.os['platform'] in invalid_platforms or \
                (self.os['platform'], int(self.os['major'])) in not_valid_versions:
            error = "The WPK for this platform is not available."
            raise WazuhInternalError(1713, extra_message=str(error))

        protocol = self._get_protocol(wpk_repo, use_http)
        if (version is None or WazuhVersion(version) >= WazuhVersion("v3.4.0")) and self.os['platform'] != "windows":
            versions_url = protocol + wpk_repo + "linux/" + self.os['arch'] + "/versions"
        else:
            if self.os['platform'] == "windows":
                versions_url = protocol + wpk_repo + "windows/versions"
            elif self.os['platform'] == "ubuntu":
                versions_url = protocol + wpk_repo + self.os['platform'] + "/" + self.os['major'] + "." + \
                               self.os['minor'] + "/" + self.os['arch'] + "/versions"
            else:
                versions_url = protocol + wpk_repo + self.os['platform'] + "/" + self.os['major'] + "/" + \
                               self.os['arch'] + "/versions"

        try:
            result = requests.get(versions_url)
        except requests.exceptions.RequestException:
            error = "Selected version repository ({}) isn't reachable".format(versions_url)
            raise WazuhInternalError(1713, extra_message=error)

        if result.ok:
            versions = [version.split() for version in result.text.split('\n')]
            versions = list(filter(lambda x: len(x) > 0, versions))
        else:
            error = "Can't access to the versions file in {}".format(versions_url)
            raise WazuhInternalError(1713, extra_message=str(error))

        return versions

    def _get_wpk_file(self, wpk_repo=common.wpk_repo_url, debug=False, version=None, force=False, use_http=False):
        """
        Search latest Wazuh WPK file for its distribution and version.
        Downloads the WPK if it is not in the upgrade folder.
        """
        # Get manager version
        manager_ = Agent(id=0)
        manager_.load_info_from_db()
        manager_ver = WazuhVersion(manager_.version)
        if debug:
            print("Manager version: {0}".format(manager_ver))

        agent_new_ver = None
        agent_new_shasum = None
        versions = self._get_versions(wpk_repo=wpk_repo, version=version, use_http=use_http)
        if not version:
            for ver in versions:
                if WazuhVersion(ver[0]) == manager_ver:
                    agent_new_ver = ver[0]
                    agent_new_shasum = ver[1]
                    break
        else:
            for ver in versions:
                if WazuhVersion(ver[0]) == WazuhVersion(version):
                    agent_new_ver = ver[0]
                    agent_new_shasum = ver[1]
                    break
        if not agent_new_ver:
            raise WazuhInternalError(1718, extra_message=version)

        # Comparing versions
        agent_ver = self.version

        if manager_ver < WazuhVersion(agent_new_ver) and not force:
            raise WazuhError(1717, extra_message="Manager: {0} / Agent: {1} -> {2}".format(manager_ver, agent_ver, agent_new_ver))

        if WazuhVersion(agent_ver) >= WazuhVersion(agent_new_ver) and not force:
            raise WazuhError(1749, extra_message="Agent: {0} -> {1}".format(agent_ver, agent_new_ver))

        if debug:
            print("Agent version: {0}".format(agent_ver))
            print("Agent new version: {0}".format(agent_new_ver))

        protocol = self._get_protocol(wpk_repo, use_http)
        # Generating file name
        if self.os['platform'] == "windows":
            wpk_file = "wazuh_agent_{0}_{1}.wpk".format(agent_new_ver, self.os['platform'])
            wpk_url = protocol + wpk_repo + "windows/" + wpk_file

        else:
            if version is None or WazuhVersion(version) >= WazuhVersion("v3.4.0"):
                wpk_file = "wazuh_agent_{0}_linux_{1}.wpk".format(agent_new_ver, self.os['arch'])
                wpk_url = protocol + wpk_repo + "linux/" + self.os['arch'] + "/" + wpk_file

            else:
                if self.os['platform'] == "ubuntu":
                    wpk_file = "wazuh_agent_{0}_{1}_{2}.{3}_{4}.wpk".format(agent_new_ver, self.os['platform'],
                                                                            self.os['major'], self.os['minor'],
                                                                            self.os['arch'])
                    wpk_url = protocol + wpk_repo + self.os['platform'] + "/" + self.os['major'] + "." + \
                              self.os['minor'] + "/" + self.os['arch'] + "/" + wpk_file
                else:
                    wpk_file = "wazuh_agent_{0}_{1}_{2}_{3}.wpk".format(agent_new_ver, self.os['platform'],
                                                                        self.os['major'], self.os['arch'])
                    wpk_url = protocol + wpk_repo + self.os['platform'] + "/" + self.os['major'] + "/" + \
                              self.os['arch'] + "/" + wpk_file

        wpk_file_path = path.join(common.ossec_path, 'var', 'upgrade', wpk_file)

        # If WPK is already downloaded
        if path.isfile(wpk_file_path):
            # Get SHA1 file sum
            sha1hash = hashlib.sha1(open(wpk_file_path, 'rb').read()).hexdigest()
            # Comparing SHA1 hash
            if not sha1hash == agent_new_shasum:
                if debug:
                    print("Downloaded file SHA1 does not match "
                          "(downloaded: {0} / repository: {1})".format(sha1hash, agent_new_shasum))
            else:
                if debug:
                    print("WPK file already downloaded: {0} - SHA1SUM: {1}".format(wpk_file_path, sha1hash))
                return [wpk_file, sha1hash]

        # Download WPK file
        if debug:
            print("Downloading WPK file from: {0}".format(wpk_url))

        try:
            result = requests.get(wpk_url)
        except requests.exceptions.RequestException as e:
            raise WazuhInternalError(1714, extra_message=str(e))

        if result.ok:
            with open(wpk_file_path, 'wb') as fd:
                for chunk in result.iter_content(chunk_size=128):
                    fd.write(chunk)
                chown(wpk_file_path, common.ossec_gid(), common.ossec_gid())
                chmod(wpk_file_path, 0o660)
        else:
            error = "Can't access to the WPK file in {}".format(wpk_url)
            raise WazuhInternalError(1714, extra_message=str(error))

        # Get SHA1 file sum
        sha1hash = hashlib.sha1(open(wpk_file_path, 'rb').read()).hexdigest()
        # Comparing SHA1 hash
        if not sha1hash == agent_new_shasum:
            raise WazuhInternalError(1714)

        if debug:
            print("WPK file downloaded: {0} - SHA1SUM: {1}".format(wpk_file_path, sha1hash))

        return [wpk_file, sha1hash]

    def _send_wpk_file(self, wpk_repo=common.wpk_repo_url, debug=False, version=None, force=False, show_progress=None,
                       chunk_size=None, rl_timeout=-1, timeout=common.open_retries, use_http=False):
        """
        Send WPK file to agent.
        """
        if not chunk_size:
            chunk_size = common.wpk_chunk_size
        # Check WPK file
        _get_wpk = self._get_wpk_file(wpk_repo=wpk_repo, debug=debug, version=version, force=force, use_http=use_http)
        wpk_file = _get_wpk[0]
        file_sha1 = _get_wpk[1]
        wpk_file_size = stat(path.join(common.ossec_path, 'var', 'upgrade', wpk_file)).st_size
        if debug:
            print("Upgrade PKG: {0} ({1} KB)".format(wpk_file, wpk_file_size / 1024))

        # Sending reset lock timeout
        s = OssecSocket(common.REQUEST_SOCKET)
        msg = "{0} com lock_restart {1}".format(str(self.id).zfill(3), str(rl_timeout))
        s.send(msg.encode())
        if debug:
            print("MSG SENT: {0}".format(str(msg)))
        data = s.receive().decode()
        s.close()
        if debug:
            print("RESPONSE: {0}".format(data))
        if not data.startswith('ok'):
            raise WazuhException(1715, data.replace("err ", ""))

        # Open file on agent
        s = OssecSocket(common.REQUEST_SOCKET)
        msg = "{0} com open wb {1}".format(str(self.id).zfill(3), wpk_file)
        s.send(msg.encode())
        if debug:
            print("MSG SENT: {0}".format(str(msg)))
        data = s.receive().decode()
        s.close()
        if debug:
            print("RESPONSE: {0}".format(data))
        counter = 0
        while data.startswith('err') and counter < timeout:
            sleep(common.open_sleep)
            counter = counter + 1
            s = OssecSocket(common.REQUEST_SOCKET)
            msg = "{0} com open wb {1}".format(str(self.id).zfill(3), wpk_file)
            s.send(msg.encode())
            if debug:
                print("MSG SENT: {0}".format(str(msg)))
            data = s.receive().decode()
            s.close()
            if debug:
                print("RESPONSE: {0}".format(data))
        if not data.startswith('ok'):
            raise WazuhInternalError(1715, extra_message=data.replace("err ", ""))

        # Sending reset lock timeout
        s = OssecSocket(common.REQUEST_SOCKET)
        msg = "{0} com lock_restart {1}".format(str(self.id).zfill(3), str(rl_timeout))
        s.send(msg.encode())
        if debug:
            print("MSG SENT: {0}".format(str(msg)))
        data = s.receive().decode()
        s.close()
        if debug:
            print("RESPONSE: {0}".format(data))
        if not data.startswith('ok'):
            raise WazuhInternalError(1715, extra_message=data.replace("err ", ""))

        # Sending file to agent
        if debug:
            print("Chunk size: {0} bytes".format(chunk_size))
        file = open(path.join(common.ossec_path, 'var', 'upgrade', wpk_file), "rb")
        if not file:
            raise WazuhInternalError(1715, extra_message=data.replace("err ", ""))
        if debug:
            print("Sending: {0}".format(path.join(common.ossec_path, 'var', 'upgrade', wpk_file)))
        try:
            # start_time = time()
            bytes_read = file.read(chunk_size)
            bytes_read_acum = 0
            while bytes_read:
                s = OssecSocket(common.REQUEST_SOCKET)
                msg = "{0} com write {1} {2} ".format(str(self.id).zfill(3), str(len(bytes_read)), wpk_file)
                s.send(msg.encode() + bytes_read)
                data = s.receive().decode()
                s.close()
                if not data.startswith('ok'):
                    raise WazuhInternalError(1715, extra_message=data.replace("err ", ""))
                bytes_read = file.read(chunk_size)
                if show_progress:
                    bytes_read_acum = bytes_read_acum + len(bytes_read)
                    show_progress(int(bytes_read_acum * 100 / wpk_file_size) +
                                  (bytes_read_acum * 100 % wpk_file_size > 0))
            # elapsed_time = time() - start_time
        finally:
            file.close()

        # Close file on agent
        s = OssecSocket(common.REQUEST_SOCKET)
        msg = "{0} com close {1}".format(str(self.id).zfill(3), wpk_file)
        s.send(msg.encode())
        if debug:
            print("MSG SENT: {0}".format(str(msg)))
        data = s.receive().decode()
        s.close()
        if debug:
            print("RESPONSE: {0}".format(data))
        if not data.startswith('ok'):
            raise WazuhInternalError(1715, extra_message=data.replace("err ", ""))

        # Get file SHA1 from agent and compare
        s = OssecSocket(common.REQUEST_SOCKET)
        msg = "{0} com sha1 {1}".format(str(self.id).zfill(3), wpk_file)
        s.send(msg.encode())
        if debug:
            print("MSG SENT: {0}".format(str(msg)))
        data = s.receive().decode()
        s.close()
        if debug:
            print("RESPONSE: {0}".format(data))
        if not data.startswith('ok '):
            raise WazuhInternalError(1715, extra_message=data.replace("err ", ""))
        rcv_sha1 = data.split(' ')[1]
        if rcv_sha1 == file_sha1:
            return ["WPK file sent", wpk_file]
        else:
            raise WazuhInternalError(1715, extra_message=data.replace("err ", ""))

    def upgrade(self, wpk_repo=None, debug=False, version=None, force=False, show_progress=None, chunk_size=None,
                rl_timeout=-1, use_http=False):
        """
        Upgrade agent using a WPK file.
        """
        if int(self.id) == 0:
            raise WazuhError(1703)

        self.load_info_from_db()

        # Check if agent is active.
        if self.status.lower() != 'active':
            raise WazuhError(1720)

        # Check if remote upgrade is available for the selected agent version
        if WazuhVersion(self.version) < WazuhVersion("3.0.0-alpha4"):
            raise WazuhError(1719, extra_message=str(version))

        if self.os['platform'] == "windows" and int(self.os['major']) < 6:
            raise WazuhInternalError(1721, extra_message=self.os['name'])

        if wpk_repo is None:
            wpk_repo = common.wpk_repo_url

        if not wpk_repo.endswith('/'):
            wpk_repo = wpk_repo + '/'

        # Send file to agent
        sending_result = self._send_wpk_file(wpk_repo=wpk_repo, debug=debug, version=version, force=force,
                                             show_progress=show_progress, chunk_size=chunk_size,
                                             rl_timeout=rl_timeout, use_http=use_http)
        if debug:
            print(sending_result[0])

        # Send upgrading command
        s = OssecSocket(common.REQUEST_SOCKET)
        if self.os['platform'] == "windows":
            msg = "{0} com upgrade {1} upgrade.bat".format(str(self.id).zfill(3), sending_result[1])
        else:
            msg = "{0} com upgrade {1} upgrade.sh".format(str(self.id).zfill(3), sending_result[1])
        s.send(msg.encode())
        if debug:
            print("MSG SENT: {0}".format(str(msg)))
        data = s.receive().decode()
        s.close()

        if debug:
            print("RESPONSE: {0}".format(data))
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        if data.startswith('ok'):
            s.sendto(("1:wazuh-upgrade:wazuh: Upgrade procedure on agent {0} ({1}): started. "
                      "Current version: {2}".format(str(self.id).zfill(3), self.name, self.version)).encode(),
                     path.join(common.ossec_path, 'queue', 'ossec', 'queue'))
            s.close()
            return "Upgrade procedure started"
        else:
            s.sendto(
                ("1:wazuh-upgrade:wazuh: Upgrade procedure on agent {0} ({1}): aborted: {2}".format(
                    str(self.id).zfill(3), self.name, data.replace("err ", ""))).encode(),
                common.ossec_path + "/queue/ossec/queue")
            s.close()
            raise WazuhError(1716, extra_message=data.replace("err ", ""))

    def upgrade_result(self, debug=False, timeout=common.upgrade_result_retries):
        """
        Read upgrade result output from agent.
        """
        sleep(1)
        if self.id == "000":
            raise WazuhError(1703)
        self.load_info_from_db()
        s = OssecSocket(common.REQUEST_SOCKET)
        msg = "{0} com upgrade_result".format(str(self.id).zfill(3))
        s.send(msg.encode())
        if debug:
            print("MSG SENT: {0}".format(str(msg)))
        data = s.receive().decode()
        s.close()
        if debug:
            print("RESPONSE: {0}".format(data))
        counter = 0
        while data.startswith('err') and counter < timeout:
            sleep(common.upgrade_result_sleep)
            counter = counter + 1
            s = OssecSocket(common.REQUEST_SOCKET)
            msg = str(self.id).zfill(3) + " com upgrade_result"
            s.send(msg.encode())
            if debug:
                print("MSG SENT: {0}".format(str(msg)))
            data = s.receive().decode()
            s.close()
            if debug:
                print("RESPONSE: {0}".format(data))
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        if data.startswith('ok 0'):
            s.sendto(("1:wazuh-upgrade:wazuh: Upgrade procedure on agent {0} ({1}): succeeded. "
                      "New version: {2}".format(str(self.id).zfill(3), self.name, self.version)).encode(),
                     path.join(common.ossec_path, 'queue', 'ossec', 'queue'))
            s.close()
            return "Agent upgraded successfully"
        elif data.startswith('ok 2'):
            s.sendto(("1:wazuh-upgrade:wazuh: Upgrade procedure on agent {0} ({1}): failed: "
                      "restored to previous version".format(str(self.id).zfill(3), self.name)).encode(),
                     path.join(common.ossec_path, 'queue', 'ossec', 'queue'))
            s.close()
            raise WazuhError(1716, extra_message="Agent restored to previous version")
        else:
            s.sendto(("1:wazuh-upgrade:wazuh: Upgrade procedure on agent {0} ({1}): lost: {2}".format(
                str(self.id).zfill(3), self.name, data.replace("err ", ""))).encode(),
                     path.join(common.ossec_path, 'queue', 'ossec', 'queue'))
            s.close()
            raise WazuhError(1716, extra_message=data.replace("err ", ""))

    def _send_custom_wpk_file(self, file_path, debug=False, show_progress=None, chunk_size=None, rl_timeout=-1,
                              timeout=common.open_retries):
        """
        Send custom WPK file to agent.
        """
        if not chunk_size:
            chunk_size = common.wpk_chunk_size

        # Check WPK file
        if not file_path or not path.isfile(file_path):
            raise WazuhError(1006, extra_message=f"File path attempted: {file_path}")

        wpk_file = path.basename(file_path)
        wpk_file_size = stat(file_path).st_size
        if debug:
            print("Custom WPK file: {0} ({1} KB)".format(wpk_file, wpk_file_size / 1024))

        # Sending reset lock timeout
        s = OssecSocket(common.REQUEST_SOCKET)
        msg = "{0} com lock_restart {1}".format(str(self.id).zfill(3), str(rl_timeout))
        s.send(msg.encode())

        if debug:
            print("MSG SENT: {0}".format(str(msg)))
        data = s.receive().decode()
        s.close()
        if debug:
            print("RESPONSE: {0}".format(data))
        if not data.startswith('ok'):
            raise WazuhInternalError(1715, extra_message=data.replace("err ", ""))

        # Open file on agent
        s = OssecSocket(common.REQUEST_SOCKET)
        msg = "{0} com open wb {1}".format(str(self.id).zfill(3), wpk_file)
        s.send(msg.encode())
        if debug:
            print("MSG SENT: {0}".format(str(msg)))
        data = s.receive().decode()
        s.close()
        if debug:
            print("RESPONSE: {0}".format(data))
        counter = 0
        while data.startswith('err') and counter < timeout:
            sleep(common.open_sleep)
            counter = counter + 1
            s = OssecSocket(common.REQUEST_SOCKET)
            msg = "{0} com open wb {1}".format(str(self.id).zfill(3), wpk_file)
            s.send(msg.encode())
            if debug:
                print("MSG SENT: {0}".format(str(msg)))
            data = s.receive().decode()
            s.close()
            if debug:
                print("RESPONSE: {0}".format(data))
        if not data.startswith('ok'):
            raise WazuhInternalError(1715, extra_message=data.replace("err ", ""))

        # Sending file to agent
        if debug:
            print("Chunk size: {0} bytes".format(chunk_size))
        file = open(file_path, "rb")
        if not file:
            raise WazuhInternalError(1715, extra_message=f"Could not read the file {file_path}")
        try:
            bytes_read = file.read(chunk_size)
            file_sha1 = hashlib.sha1(bytes_read)
            bytes_read_acum = 0
            while bytes_read:
                s = OssecSocket(common.REQUEST_SOCKET)
                msg = "{0} com write {1} {2} ".format(str(self.id).zfill(3), str(len(bytes_read)), wpk_file)
                s.send(msg.encode() + bytes_read)
                data = s.receive().decode()
                s.close()
                if not data.startswith('ok'):
                    raise WazuhException(1715, data.replace("err ", ""))
                bytes_read = file.read(chunk_size)
                file_sha1.update(bytes_read)
                if show_progress:
                    bytes_read_acum = bytes_read_acum + len(bytes_read)
                    show_progress(int(bytes_read_acum * 100 / wpk_file_size) +
                                  (bytes_read_acum * 100 % wpk_file_size > 0))
            calc_sha1 = file_sha1.hexdigest()
            if debug:
                print("FILE SHA1: {0}".format(calc_sha1))
        finally:
            file.close()

        # Close file on agent
        s = OssecSocket(common.REQUEST_SOCKET)
        msg = "{0} com close {1}".format(str(self.id).zfill(3), wpk_file)
        s.send(msg.encode())
        if debug:
            print("MSG SENT: {0}".format(str(msg)))
        data = s.receive().decode()
        s.close()
        if debug:
            print("RESPONSE: {0}".format(data))
        if not data.startswith('ok'):
            raise WazuhInternalError(1715, extra_message=data.replace("err ", ""))

        # Get file SHA1 from agent and compare
        s = OssecSocket(common.REQUEST_SOCKET)
        msg = "{0} com sha1 {1}".format(str(self.id).zfill(3), wpk_file)
        s.send(msg.encode())
        if debug:
            print("MSG SENT: {0}".format(str(msg)))
        data = s.receive().decode()
        s.close()
        if debug:
            print("RESPONSE: {0}".format(data))
        if not data.startswith('ok '):
            raise WazuhInternalError(1715, extra_message=data.replace("err ", ""))
        rcv_sha1 = data.split(' ')[1]
        if calc_sha1 == rcv_sha1:
            return ["WPK file sent", wpk_file]
        else:
            raise WazuhInternalError(1715, extra_message=data.replace("err ", ""))

    def upgrade_custom(self, file_path, installer=None, debug=False, show_progress=None, chunk_size=None, rl_timeout=-1):
        """
        Upgrade agent using a custom WPK file.
        """
        if self.id == "000":
            raise WazuhError(1703)

        self.load_info_from_db()

        # Check if agent is active.
        if self.status.lower() != 'active':
            raise WazuhException(1720)

        # Send file to agent
        sending_result = self._send_custom_wpk_file(file_path, debug, show_progress, chunk_size, rl_timeout)
        if debug:
            print(sending_result[0])

        # Send installing command
        s = OssecSocket(common.REQUEST_SOCKET)
        installer = installer if installer is not None \
            else 'upgrade.bat' if self.os['platform'] == 'windows' else 'upgrade.sh'
        msg = "{0} com upgrade {1} {2}".format(str(self.id).zfill(3), sending_result[1], installer)
        s.send(msg.encode())
        if debug:
            print("MSG SENT: {0}".format(str(msg)))
        data = s.receive().decode()
        s.close()
        if debug:
            print("RESPONSE: {0}".format(data))
        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        if data.startswith('ok'):
            s.sendto(("1:wazuh-upgrade:wazuh: Custom installation on agent {0} ({1}): started.".format(
                str(self.id).zfill(3), self.name)).encode(), path.join(common.ossec_path, "queue", "ossec", "queue"))
            s.close()
            return "Installation started"
        else:
            s.sendto(("1:wazuh-upgrade:wazuh: "
                      "Custom installation on agent {0} ({1}): aborted: {2}".format(str(self.id).zfill(3),
                                                                                    self.name, data.replace("err ", ""))
                      ).encode(),
                     path.join(common.ossec_path, "queue", "ossec", "queue"))
            s.close()
            raise WazuhError(1716, extra_message=f'{data.replace("err ", "")}. '
                                                 f'It is possible that the agent has been disconnected '
                                                 f'or a timeout has occurred in the call')

    def getconfig(self, component, config):
        """Read agent loaded configuration.
        """
        # checks if agent version is compatible with this feature
        self.load_info_from_db()
        if self.version is None:
            raise WazuhInternalError(1015)

        agent_version = WazuhVersion(self.version.split(" ")[1])
        required_version = WazuhVersion("v3.7.0")
        if agent_version < required_version:
            raise WazuhInternalError(1735, extra_message="Minimum required version is " + str(required_version))

        return configuration.get_active_configuration(self.id, component, config)


def format_fields(field_name, value, today, lastKeepAlive=None, version=None):
    if field_name == 'id':
        return str(value).zfill(3)
    elif field_name == 'status':
        return calculate_status(lastKeepAlive, version is None, today)
    elif field_name == 'group':
        return value.split(',')
    elif field_name in ['dateAdd', 'lastKeepAlive']:
        return datetime.utcfromtimestamp(value) if not isinstance(value, str) else value
    else:
        return value


def calculate_status(last_keep_alive, pending, today=datetime.utcnow()):
    """Calculates state based on last keep alive
    """
    if not last_keep_alive or last_keep_alive == 'unknown':
        return "never_connected"
    else:
        last_date = datetime.utcfromtimestamp(last_keep_alive)
        difference = (today - last_date).total_seconds()
        return "disconnected" if difference > common.limit_seconds else ("pending" if pending else "active")


def send_restart_command(agent_id):
    """ Send restart command to an agent

    :param agent_id: Agent ID
    :return OSSEC message
    """
    oq = OssecQueue(common.ARQUEUE)
    ret_msg = oq.send_msg_to_agent(OssecQueue.RESTART_AGENTS, agent_id)
    oq.close()

    return ret_msg

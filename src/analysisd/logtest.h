/* Copyright (C) 2015-2020, Wazuh Inc.
 * Copyright (C) 2009 Trend Micro Inc.
 * All right reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#include "shared.h"
#include "rules.h"
#include "decoders/decoder.h"
#include "lists.h"

typedef struct sessionLogtest {

    int fd;

    RuleNode *rulelist;
    OSDecoderNode *decoderlist_forpname;
    OSDecoderNode *decoderlist_nopname;
    ListNode *cdblistnode;
    ListRule *cdblistrule;

} sessionLogtest;

/**
 * @brief Main function of Wazuh Logtest module. Listen and treat conexions with clients.
 */
void wazuh_logtest();

/**
 * @brief Create resources necessaries to service client
 * @param fd File descriptor which represents the client
 */
void w_initialize_session(int fd);

/**
 * @brief Process client's request
 * @param fd File descriptor which represents the client
 */
void w_process_request(int fd);

/**
 * @brief Free resources after client close connection
 * @param fd File descriptor which represents the client
 */
void w_remove_session(int fd);

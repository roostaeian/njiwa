/*
 * Njiwa Open Source Embedded M2M UICC Remote Subscription Manager
 * 
 * 
 * Copyright (C) 2019 - , Digital Solutions Ltd. - http://www.dsmagic.com
 *
 * Njiwa Dev <dev@njiwa.io>
 * 
 * This program is free software, distributed under the terms of
 * the GNU General Public License.
 */ 

package io.njiwa.common.rest.types;

/**
 * Created by bagyenda on 06/06/2017.
 */
public class Roles {
    public static final String EntityAdminUser = "Entity-Admin";
    public static final String EntityUser = "Entity-User";
    public static final String SystemAdminUser = "SysAdmin";
    public static final String SystemUser = "SysUser";
    public  static final String ALLOWALL = "*"; // For all access
    public static final String[] ALL_ROLES = {EntityAdminUser, EntityUser, SystemUser, ALLOWALL, SystemAdminUser
    };

}

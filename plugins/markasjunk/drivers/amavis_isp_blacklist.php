<?php

/**
 * AmavisD with ISPConfig3 Blacklist driver
 *
 * @version 1.0
 *
 * @author Der-Jan
 *
 * Copyright (C) 2014 Der-Jan
 *
 * Modify by 2021 sp4148
 *
 * This driver is part of the MarkASJunk plugin for Roundcube.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Roundcube. If not, see https://www.gnu.org/licenses/.
$sql_select_policy =
   'SELECT *,spamfilter_users.id'.
      ' FROM spamfilter_users LEFT JOIN spamfilter_policy ON spamfilter_users.policy_id=spamfilter_policy.id'.
         ' WHERE spamfilter_users.email IN (%k) ORDER BY spamfilter_users.priority DESC';
$sql_select_white_black_list = 'SELECT wb FROM spamfilter_wblist'.
            ' WHERE (spamfilter_wblist.rid=?) AND (spamfilter_wblist.email IN (%k))' .
                ' ORDER BY spamfilter_wblist.priority DESC';
 */

$form["auth_preset"]["userid"]  = 0; // 0 = id of the user, > 0 id must match with id of current user
$form["auth_preset"]["groupid"] = 0; // 0 = default groupid of the user, > 0 id must match with groupid of current user
$form["auth_preset"]["perm_user"] = 'riud'; //r = read, i = insert, u = update, d = delete
$form["auth_preset"]["perm_group"] = 'riud'; //r = read, i = insert, u = update, d = delete
$form["auth_preset"]["perm_other"] = ''; //r = read, i = insert, u = update, d = delete

class markasjunk_amavis_isp_blacklist
{
    private $user_email = '';

    public function spam($uids, $src_mbox, $dst_mbox)
    {
        $this->_do_list($uids, true);
    }

    public function ham($uids, $src_mbox, $dst_mbox)
    {
        $this->_do_list($uids, false);
    }

    private function _do_list($uids, $spam)
    {
        $rcube = rcube::get_instance();
        $this->user_email = $rcube->user->data['username'];

        if (is_file($rcube->config->get('markasjunk_amacube_config')) && !$rcube->config->load_from_file($rcube->config->get('markasjunk_amacube_config'))) {
            rcube::raise_error(array('code' => 527, 'type' => 'php',
                'file' => __FILE__, 'line' => __LINE__,
                'message' => "Failed to load config from " . $rcube->config->get('markasjunk_amacube_config')
            ), true, false);

            return false;
        }

        $db = rcube_db::factory($rcube->config->get('amacube_db_dsn'), '', true);
        $db->set_debug((bool) $rcube->config->get('sql_debug'));
        $db->db_connect('w');

        $debug = $rcube->config->get('markasjunk_debug');

        // check DB connections and exit on failure
        if ($err_str = $db->is_error()) {
            rcube::raise_error(array(
        foreach ($uids as $uid) {
            $message = new rcube_message($uid);
            $email = $message->sender['mailto'];
            $sql_result = $db->query("SELECT `wblist_id` FROM `spamfilter_wblist` WHERE `email` = ? ORDER BY `priority` DESC", $email);

            if ($sql_result && ($res_array = $db->fetch_assoc($sql_result))) {
                $sid = $res_array['wblist_id'];
            }
            else {
                if ($debug) {
                    rcube::write_log('markasjunk', $email . ' not found in mailaddr table - add it');
                }

                $sql_result = $db->query("INSERT INTO `spamfilter_wblist` ( `priority`, `email`, `rid`, `server_id`, `sys_userid`,`sys_perm_user`, `sys_perm_group`) VALUES ( 6, ?, ? , ?, ?, ?, ?)", $email, $rid, $server_id, $sys_userid, $sys_perm_user, $sys_perm_group);
                if ($sql_result) {
                    $sid = $db->insert_id();
                }
                else {
                    if ($debug) {
                        rcube::write_log('markasjunk', 'Cannot add ' . $email . ' to mailaddr table: ' . $db->is_error($sql_result));
                    }

                    return false;
                }
            }

            $wb = '';
            $sql_result = $db->query("SELECT `wb` FROM `spamfilter_wblist` WHERE `wblist_id` = ? AND `rid` =?", $sid, $rid);
            if ($sql_result && ($res_array = $db->fetch_assoc($sql_result))) {
                $wb = $res_array['wb'];
            }

            if (!$wb || (!$spam && preg_match('/^([BbNnFf])[\s]*\z/', $wb)) || ($spam && preg_match('/^([WwYyTt])[\s]*\z/', $wb))) {
                $newwb = 'w';

                if ($spam) {
                    $newwb = 'b';
                }

                if ($wb) {
                    $sql_result = $db->query('UPDATE `spamfilter_wblist` SET `wb` = ? WHERE `wblist_id` = ? AND `rid` = ?',
                    $newwb, $sid, $rid);
                }
                else {
                    $sql_result = $db->query('INSERT INTO `spamfilter_wblist` (`wblist_id`, `rid`, `wb`) VALUES (?,?,?)',
                    $sid, $rid, $newwb);
                }

                if (!$sql_result) {
                    if ($debug) {
                        rcube::write_log('markasjunk', 'Cannot update wblist for user ' . $this->user_email . ' with ' . $email);
                    }

                    return false;
                }
            }
        }
    }
}

                'code'    => 603,
                'type'    => 'db',
                'message' => $err_str
            ), false, true);
        }

        // Getting email from data record
        $sql_result = $db->query("SELECT `server_id`, `sys_userid`, `sys_perm_user`, `sys_perm_group` FROM `mail_user` WHERE `email` = ?", $this->user_email);
        if ($sql_result && ($res_array = $db->fetch_assoc($sql_result))) {
            $server_id = $res_array['server_id'];
            $sys_userid = $res_array['sys_userid'];
            $sys_perm_user = $res_array['sys_perm_user'];
            $sys_perm_group = $res_array['sys_perm_group'];
        }

        $sql_result = $db->query("SELECT `id` FROM `spamfilter_users` WHERE `email` = ?", $this->user_email);
        if ($sql_result && ($res_array = $db->fetch_assoc($sql_result))) {
            $rid = $res_array['id'];

                rcube::write_log('markasjunk', $this->user_email . ' found in users table');
        }
        else {
            if ($debug) {
                rcube::write_log('markasjunk', $this->user_email . ' not found in users table');
            }

            return false;
        }

        foreach ($uids as $uid) {
            $message = new rcube_message($uid);
            $email = $message->sender['mailto'];
            $sql_result = $db->query("SELECT `wblist_id` FROM `spamfilter_wblist` WHERE `email` = ? ORDER BY `priority` DESC", $email);

            if ($sql_result && ($res_array = $db->fetch_assoc($sql_result))) {
                $sid = $res_array['wblist_id'];
            }
            else {
                if ($debug) {
                    rcube::write_log('markasjunk', $email . ' not found in mailaddr table - add it');
                }

                $sql_result = $db->query("INSERT INTO `spamfilter_wblist` ( `priority`, `email`, `rid`, `server_id`, `sys_userid`,`sys_perm_user`, `sys_perm_group`) VALUES ( 6, ?, ? , ?, ?, ?, ?)", $email, $rid, $server_id, $sys_userid, $sys_perm_user, $sys_perm_group);
                if ($sql_result) {
                    $sid = $db->insert_id();
                }
                else {
                    if ($debug) {
                        rcube::write_log('markasjunk', 'Cannot add ' . $email . ' to mailaddr table: ' . $db->is_error($sql_result));
                    }

                    return false;
                }
            }

            $wb = '';
            $sql_result = $db->query("SELECT `wb` FROM `spamfilter_wblist` WHERE `wblist_id` = ? AND `rid` =?", $sid, $rid);
            if ($sql_result && ($res_array = $db->fetch_assoc($sql_result))) {
                $wb = $res_array['wb'];
            }

            if (!$wb || (!$spam && preg_match('/^([BbNnFf])[\s]*\z/', $wb)) || ($spam && preg_match('/^([WwYyTt])[\s]*\z/', $wb))) {
                $newwb = 'w';

                if ($spam) {
                    $newwb = 'b';
                }

                if ($wb) {
                    $sql_result = $db->query('UPDATE `spamfilter_wblist` SET `wb` = ? WHERE `wblist_id` = ? AND `rid` = ?',
                    $newwb, $sid, $rid);
                }
                else {
                    $sql_result = $db->query('INSERT INTO `spamfilter_wblist` (`wblist_id`, `rid`, `wb`) VALUES (?,?,?)',
                    $sid, $rid, $newwb);
                }

                if (!$sql_result) {
                    if ($debug) {
                        rcube::write_log('markasjunk', 'Cannot update wblist for user ' . $this->user_email . ' with ' . $email);
                    }

                    return false;
                }
            }
        }
    }
}

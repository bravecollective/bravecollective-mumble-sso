<?php
if (!defined('GUEST')) {
    die('go away');
}

try {
    $DB_CONNECTION = new PDO($cfg_sql_url, $cfg_sql_user, $cfg_sql_pass);
} catch (PDOException $e) {
    $_SESSION['error_code'] = 50;
    $_SESSION['error_message'] = 'Failed to connect to the database.';
    return false;
}

/**
 * @param int $length
 * @return string
 */
function krand($length)
{
    $alphabet = "abcdefghkmnpqrstuvwxyzABCDEFGHKMNPQRSTUVWXYZ23456789";
    $pass = "";
    for ($i = 0; $i < $length; $i++) {
        $pass = $pass . substr($alphabet, hexdec(bin2hex(openssl_random_pseudo_bytes(1))) % strlen($alphabet), 1);
    }

    return $pass;
}

/**
 *
 */
function sstart()
{
    global $_SESSION;

    session_start();

    if (!isset($_SESSION['nonce'])) {
        $_SESSION['nonce'] = krand(22);
    }
}

/**
 *
 */
function sdestroy()
{
    global $_SESSION;

    $_SESSION = [];
    if (ini_get("session.use_cookies")) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', time() - 42000, $params["path"], $params["domain"], $params["secure"], $params["httponly"]);
    }
    session_destroy();
}

/**
 * @param string $name
 * @return string
 */
function toMumbleName($name)
{
    return strtolower(preg_replace("/[^A-Za-z0-9\-]/", '_', $name));
}

/**
 * @return bool
 */
function sso_update()
{
    global $cfg_ccp_client_id, $cfg_ccp_client_secret, $cfg_user_agent, $DB_CONNECTION, $cfg_restrict_access_by_ticker, $_SESSION, $_GET;

    // ---- Check parameters

    if (!isset($_GET['state'])) {
        $_SESSION['error_code'] = 10;
        $_SESSION['error_message'] = 'State not found.';

        return false;
    }
    $sso_state = $_GET['state'];

    if (!isset($_GET['code'])) {
        $_SESSION['error_code'] = 11;
        $_SESSION['error_message'] = 'Code not found.';

        return false;
    }
    $sso_code = $_GET['code'];

    if (!isset($_SESSION['nonce'])) {
        $_SESSION['error_code'] = 12;
        $_SESSION['error_message'] = 'Nonce not found.';

        return false;
    }
    $nonce = $_SESSION['nonce'];

    // ---- Verify nonce

    if ($nonce != $sso_state) {
        $_SESSION['error_code'] = 20;
        $_SESSION['error_message'] = 'Nonce is out of sync.';

        return false;
    }

    // ---- Translate code to token

    $data = http_build_query(
        [
            'grant_type' => 'authorization_code',
            'code' => $sso_code,
        ]
    );
    $options = [
        'http' => [
            'method' => 'POST',
            'header' => [
                'Authorization: Basic ' . base64_encode($cfg_ccp_client_id . ':' . $cfg_ccp_client_secret),
                'Content-type: application/x-www-form-urlencoded',
                'Host: login.eveonline.com',
                'User-Agent: ' . $cfg_user_agent,
            ],
            'content' => $data,
        ],
    ];
    $result = file_get_contents('https://login.eveonline.com/oauth/token', false, stream_context_create($options));

    if (!$result) {
        $_SESSION['error_code'] = 30;
        $_SESSION['error_message'] = 'Failed to convert code to token.';

        return false;
    }
    $sso_token = json_decode($result)->access_token;

    // ---- Translate token to character

    $options = [
        'http' => [
            'method' => 'GET',
            'header' => [
                'Authorization: Bearer ' . $sso_token,
                'Host: login.eveonline.com',
                'User-Agent: ' . $cfg_user_agent,
            ],
        ],
    ];
    $result = file_get_contents('https://login.eveonline.com/oauth/verify', false, stream_context_create($options));

    if (!$result) {
        $_SESSION['error_code'] = 40;
        $_SESSION['error_message'] = 'Failed to convert token to character.';

        return false;
    }

    $json = json_decode($result);
    $character_id = $json->CharacterID;
    $owner_hash = $json->CharacterOwnerHash;

    // ---- Character details

    $affiliation = character_affiliation(array($character_id));
    if (!is_array($affiliation)) {
        $_SESSION['error_code'] = 81;
        $_SESSION['error_message'] = 'Failed to connect to EVE API try again later.';

        return false;
    }

    $character_name = (string)$affiliation[0]['character_name'];
    $corporation_id = (int)$affiliation[0]['corporation_id'];
    $corporation_name = (string)$affiliation[0]['corporation_name'];
    $alliance_id = (int)$affiliation[0]['alliance_id'];
    $alliance_name = (string)$affiliation[0]['alliance_name'];

    $characters_groups = core_groups([$character_id]);
    $groups = isset($characters_groups[(int)$character_id]) ? (string)$characters_groups[(int)$character_id] : fetch_fallback_groups($corporation_id, $alliance_id);

    $mumble_username = toMumbleName($character_name);
    $updated_at = time();

    // ---- Access Restrictions

    if ($cfg_restrict_access_by_ticker > 0) {
        $stm = $DB_CONNECTION->prepare('SELECT * FROM ticker WHERE filter = :filter');
        $stm->bindValue(':filter', 'alliance-' . $alliance_id);
        if (!$stm->execute()) {
            $_SESSION['error_code'] = 70;
            $_SESSION['error_message'] = 'Failed to query ticker database for alliance.';
            $arr = $stm->ErrorInfo();
            error_log('SQL failure:' . $arr[0] . ':' . $arr[1] . ':' . $arr[2]);

            return false;
        }
        $rowa = $stm->fetch();

        $stm = $DB_CONNECTION->prepare('SELECT * FROM ticker WHERE filter = :filter');
        $stm->bindValue(':filter', 'corporation-' . $corporation_id);
        if (!$stm->execute()) {
            $_SESSION['error_code'] = 71;
            $_SESSION['error_message'] = 'Failed to query ticker database for corporation.';
            $arr = $stm->ErrorInfo();
            error_log('SQL failure:' . $arr[0] . ':' . $arr[1] . ':' . $arr[2]);

            return false;
        }
        $rowc = $stm->fetch();

        if ($cfg_restrict_access_by_ticker == 1 && !($rowa || $rowc)) {
            $_SESSION['error_code'] = 72;
            $_SESSION['error_message'] = 'Access to this server is for members of specific corporations and alliances only.';

            return false;
        }
        if ($cfg_restrict_access_by_ticker == 2 && !($rowa && $rowc)) {
            $_SESSION['error_code'] = 73;
            $_SESSION['error_message'] = 'Access to this server is for members of specific corporations and alliances only.';

            return false;
        }
    }

    // ---- Banning

    $stm = $DB_CONNECTION->prepare('SELECT * FROM ban WHERE filter = :filter');
    $stm->bindValue(':filter', 'alliance-' . $alliance_id);
    if (!$stm->execute()) {
        $_SESSION['error_code'] = 80;
        $_SESSION['error_message'] = 'Failed to query ban database for alliance.';
        $arr = $stm->ErrorInfo();
        error_log('SQL failure:' . $arr[0] . ':' . $arr[1] . ':' . $arr[2]);

        return false;
    }
    if ($row = $stm->fetch()) {
        $_SESSION['error_code'] = 81;
        $_SESSION['error_message'] = 'Your alliance is banned. Reason: ' . htmlentities($row['reason_public']);

        return false;
    }

    $stm = $DB_CONNECTION->prepare('SELECT * FROM ban WHERE filter = :filter');
    $stm->bindValue(':filter', 'corporation-' . $corporation_id);
    if (!$stm->execute()) {
        $_SESSION['error_code'] = 82;
        $_SESSION['error_message'] = 'Failed to query ban database for character.';
        $arr = $stm->ErrorInfo();
        error_log('SQL failure:' . $arr[0] . ':' . $arr[1] . ':' . $arr[2]);

        return false;
    }
    if ($row = $stm->fetch()) {
        $_SESSION['error_code'] = 83;
        $_SESSION['error_message'] = 'Your corporation is banned. Reason: ' . htmlentities($row['reason_public']);

        return false;
    }

    $stm = $DB_CONNECTION->prepare('SELECT * FROM ban WHERE filter = :filter');
    $stm->bindValue(':filter', 'character-' . $character_id);
    if (!$stm->execute()) {
        $_SESSION['error_code'] = 84;
        $_SESSION['error_message'] = 'Failed to query ban database for character.';
        $arr = $stm->ErrorInfo();
        error_log('SQL failure:' . $arr[0] . ':' . $arr[1] . ':' . $arr[2]);

        return false;
    }
    if ($row = $stm->fetch()) {
        $_SESSION['error_code'] = 85;
        $_SESSION['error_message'] = 'You are banned. Reason: ' . htmlentities($row['reason_public']);

        return false;
    }

    // ---- Update database

    addMissingTickersToDatabase([
        [
            'type' => 'corporation',
            'id' => $corporation_id
        ],
        [
            'type' => 'alliance',
            'id' => $alliance_id
        ]
    ]);

    $stm = $DB_CONNECTION->prepare('SELECT * FROM user WHERE character_id = :character_id');
    $stm->bindValue(':character_id', $character_id);
    if (!$stm->execute()) {
        $_SESSION['error_code'] = 90;
        $_SESSION['error_message'] = 'Failed to retrieve user.';
        $arr = $stm->ErrorInfo();
        error_log('SQL failure:' . $arr[0] . ':' . $arr[1] . ':' . $arr[2]);

        return false;
    }

    $mumble_password = krand(10);

    $mumbleFullName = generateMumbleFullName($character_name, $corporation_id, $alliance_id, $groups);

    if ($row = $stm->fetch()) {
        if ($owner_hash == $row['owner_hash']) {
            $mumble_password = $row['mumble_password'];
        }
        $stm = $DB_CONNECTION->prepare('UPDATE user set character_name = :character_name, corporation_id = :corporation_id, corporation_name = :corporation_name, alliance_id = :alliance_id, alliance_name = :alliance_name, mumble_username = :mumble_username, mumble_password = :mumble_password, `groups` = :groups, updated_at = :updated_at, owner_hash = :owner_hash, mumble_fullname = :mumble_fullname WHERE character_id = :character_id');
    } else {
        $stm = $DB_CONNECTION->prepare('INSERT INTO user (character_id, character_name, corporation_id, corporation_name, alliance_id, alliance_name, mumble_username, mumble_password, `groups`, created_at, updated_at, owner_hash, mumble_fullname) VALUES (:character_id, :character_name, :corporation_id, :corporation_name, :alliance_id, :alliance_name, :mumble_username, :mumble_password, :groups, :created_at, :updated_at, :owner_hash, :mumble_fullname)');
        $stm->bindValue(':created_at', $updated_at);
    }

    $stm->bindValue(':character_id', $character_id);
    $stm->bindValue(':character_name', $character_name);
    $stm->bindValue(':corporation_id', $corporation_id);
    $stm->bindValue(':corporation_name', $corporation_name);
    $stm->bindValue(':alliance_id', $alliance_id);
    $stm->bindValue(':alliance_name', $alliance_name);
    $stm->bindValue(':mumble_username', $mumble_username);
    $stm->bindValue(':mumble_password', $mumble_password);
    $stm->bindValue(':groups', $groups);
    $stm->bindValue(':updated_at', $updated_at);
    $stm->bindValue(':owner_hash', $owner_hash);
    $stm->bindValue(':mumble_fullname', $mumbleFullName);
    if (!$stm->execute()) {
        $_SESSION['error_code'] = 92;
        $_SESSION['error_message'] = 'Failed to insert or update user.';
        $arr = $stm->ErrorInfo();
        error_log('SQL failure:' . $arr[0] . ':' . $arr[1] . ':' . $arr[2]);

        return false;
    }

    // ---- Success

    $_SESSION['error_code'] = 0;
    $_SESSION['error_message'] = 'OK';

    $_SESSION['character_id'] = $character_id;
    $_SESSION['character_name'] = $character_name;
    $_SESSION['corporation_id'] = $corporation_id;
    $_SESSION['corporation_name'] = $corporation_name;
    $_SESSION['alliance_id'] = $alliance_id;
    $_SESSION['alliance_name'] = $alliance_name;

    $_SESSION['mumble_username'] = $mumble_username;
    $_SESSION['mumble_password'] = $mumble_password;
    $_SESSION['groups'] = $groups;

    $_SESSION['updated_at'] = $updated_at;

    return true;
}

/**
 * @param int $character_id
 * @return bool
 */
function update_character($character_id)
{
    global $DB_CONNECTION;

    $character_id = (int)$character_id;
    $affiliation = character_affiliation([$character_id]);
    if (!is_array($affiliation)) {
        $_SESSION['error_code'] = 81;
        $_SESSION['error_message'] = 'Failed to connect to EVE API, try again later.';

        return false;
    }

    $character_name = (string)$affiliation[0]['character_name'];
    $corporation_id = (int)$affiliation[0]['corporation_id'];
    $corporation_name = (string)$affiliation[0]['corporation_name'];
    $alliance_id = (int)$affiliation[0]['alliance_id'];
    $alliance_name = (string)$affiliation[0]['alliance_name'];

    $characters_groups = core_groups([$character_id]);
    $groups = isset($characters_groups[$character_id]) ? (string)$characters_groups[$character_id] : fetch_fallback_groups($corporation_id, $alliance_id);

    $updated_at = time();
    $mumbleFullName = generateMumbleFullName($character_name, $corporation_id, $alliance_id, $groups);

    $stm = $DB_CONNECTION->prepare('UPDATE user set character_name = :character_name, corporation_id = :corporation_id, corporation_name = :corporation_name, alliance_id = :alliance_id, alliance_name = :alliance_name, `groups` = :groups, updated_at = :updated_at, mumble_fullname = :mumble_fullname WHERE character_id = :character_id');
    $stm->bindValue(':character_id', $character_id);
    $stm->bindValue(':character_name', $character_name);
    $stm->bindValue(':corporation_id', $corporation_id);
    $stm->bindValue(':corporation_name', $corporation_name);
    $stm->bindValue(':alliance_id', $alliance_id);
    $stm->bindValue(':alliance_name', $alliance_name);
    $stm->bindValue(':groups', $groups);
    $stm->bindValue(':updated_at', $updated_at);
    $stm->bindValue(':mumble_fullname', $mumbleFullName);
    if (!$stm->execute()) {
        $arr = $stm->ErrorInfo();
        error_log('SQL failure:' . $arr[0] . ':' . $arr[1] . ':' . $arr[2]);

        return false;
    }

    return true;
}

/**
 * @return bool
 */
function pass_update()
{
    global $DB_CONNECTION, $_SESSION, $_GET;

    // ---- Verify access

    if (!isset($_SESSION['character_id']) || $_SESSION['character_id'] == 0) {
        $_SESSION['error_code'] = 100;
        $_SESSION['error_message'] = 'User not found.';

        return false;
    }
    $character_id = $_SESSION['character_id'];

    if (!isset($_SESSION['nonce'])) {
        $_SESSION['error_code'] = 101;
        $_SESSION['error_message'] = 'Nonce not found in session.';

        return false;
    }
    if (!isset($_GET['n'])) {
        $_SESSION['error_code'] = 102;
        $_SESSION['error_message'] = 'Nonce not found in url.';

        return false;
    }

    if ($_SESSION['nonce'] != $_GET['n']) {
        $_SESSION['error_code'] = 103;
        $_SESSION['error_message'] = 'Nonces dont match.';

        return false;
    }

    // ---- Update user

    $mumble_password = krand(10);

    $stm = $DB_CONNECTION->prepare('UPDATE user SET mumble_password = :mumble_password WHERE character_id = :character_id');
    $stm->bindValue(':character_id', $character_id);
    $stm->bindValue(':mumble_password', $mumble_password);

    if (!$stm->execute()) {
        $_SESSION['error_code'] = 105;
        $_SESSION['error_message'] = 'Failed to update password.';
        $arr = $stm->ErrorInfo();
        error_log('SQL failure:' . $arr[0] . ':' . $arr[1] . ':' . $arr[2]);

        return false;
    }
    if (!$stm->rowCount() > 0) {
        $_SESSION['error_code'] = 106;
        $_SESSION['error_message'] = 'Unknown user for password update.';

        return false;
    }

    // ---- Success

    $_SESSION['error_code'] = 0;
    $_SESSION['error_message'] = 'OK';

    $_SESSION['mumble_password'] = $mumble_password;

    return true;
}

/**
 * @param int[] $full_character_id_array
 * @return array|false
 */
function character_affiliation($full_character_id_array)
{
    global $cfg_user_agent;

    if (is_array($full_character_id_array)) {
        $full_character_id_array = array_unique($full_character_id_array, SORT_NUMERIC);
    } else {
        $full_character_id_array = [$full_character_id_array];
    }

    $affiliations = [];
    $character_ids = [];
    $corporation_ids = [];
    $alliance_ids = [];

    // Lookup character affiliations
    foreach (array_chunk($full_character_id_array, 999) as $character_id_array) {
        $affiliation_query = json_encode(array_values($character_id_array));

        $curl = curl_init('https://esi.evetech.net/latest/characters/affiliation/');
        curl_setopt_array($curl, [
                CURLOPT_FAILONERROR => true,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_MAXREDIRS => 5,
                CURLOPT_TIMEOUT => 30,
                CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
                CURLOPT_USERAGENT => $cfg_user_agent,
                CURLOPT_HTTPHEADER => [
                    'Content-type: application/json',
                    'Content-length: ' . strlen($affiliation_query)
                ],
                CURLOPT_CUSTOMREQUEST => 'POST',
                CURLOPT_POSTFIELDS => $affiliation_query
            ]
        );
        $response = curl_exec($curl);
        if (!$response) {
            $_SESSION['error_code'] = 60;
            $_SESSION['error_message'] = 'Failed to retrieve character affiliation.';

            return false;
        }
        curl_close($curl);

        // Merge chunk affiliations into the full list of affiliations, collect char/corp/alliance ids
        $chunk_affiliations = json_decode($response, true);
        $affiliations = array_merge($affiliations, $chunk_affiliations);
        $character_ids = array_merge($character_ids, array_column($chunk_affiliations, 'character_id'));
        $corporation_ids = array_merge($corporation_ids, array_column($chunk_affiliations, 'corporation_id'));
        $alliance_ids = array_merge($alliance_ids, array_column($chunk_affiliations, 'alliance_id'));
    }

    // Filter out duplicate ids
    $character_ids = array_unique($character_ids, SORT_NUMERIC);
    $corporation_ids = array_unique($corporation_ids, SORT_NUMERIC);
    $alliance_ids = array_unique($alliance_ids, SORT_NUMERIC);

    $character_names = [];
    foreach ($character_ids as $character_id) {
        $character_info_string = file_get_contents(sprintf('https://esi.evetech.net/latest/characters/%s/', (string)$character_id));
        $character_info = json_decode($character_info_string, true);
        $character_names[(int)$character_id] = $character_info['name'];
    }
    
    $corporation_names = [];
    $alliance_names = [];
    $all_ids = array_merge($corporation_ids, $alliance_ids);

    // Query all ids to get their names.
    foreach (array_chunk($all_ids, 999) as $query_ids) {
        $name_query = json_encode(array_values($query_ids));

        $curl = curl_init('https://esi.evetech.net/latest/universe/names/');
        curl_setopt_array($curl, [
                CURLOPT_FAILONERROR => true,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_MAXREDIRS => 5,
                CURLOPT_TIMEOUT => 30,
                CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
                CURLOPT_USERAGENT => $cfg_user_agent,
                CURLOPT_HTTPHEADER => [
                    'Content-type: application/json',
                    'Content-length: ' . strlen($name_query)
                ],
                CURLOPT_CUSTOMREQUEST => 'POST',
                CURLOPT_POSTFIELDS => $name_query
            ]
        );
        $response = curl_exec($curl);
        if (!$response) {
            // Temporary fix for ESI issue
            continue;
            $_SESSION['error_code'] = 61;
            $_SESSION['error_message'] = 'Failed to retrieve affiliation names.';

            return false;
        }
        curl_close($curl);
        $names = json_decode($response);

        // Populate id => name mappings
        foreach ($names as $name) {
            if ((string)$name->category == "character") {
                $character_names[(int)$name->id] = (string)$name->name;
            }
            if ((string)$name->category == "corporation") {
                $corporation_names[(int)$name->id] = (string)$name->name;
            }
            if ((string)$name->category == "alliance") {
                $alliance_names[(int)$name->id] = (string)$name->name;
            }
        }
    }

    $affiliation_count = count($affiliations);
    for ($i = 0; $i < $affiliation_count; $i++) {
        $affiliations[$i]['character_name'] = $character_names[$affiliations[$i]['character_id']];
        $affiliations[$i]['corporation_name'] = $corporation_names[$affiliations[$i]['corporation_id']] ?? '';
        $affiliations[$i]['alliance_name'] = $alliance_names[$affiliations[$i]['alliance_id']] ?? '';
    }

    return $affiliations;
}

/**
 * @param int[] $character_id_array
 * @return array|bool
 */
function core_groups($character_id_array)
{
    // Grab core groups

    global $cfg_core_api;
    global $cfg_core_app_id;
    global $cfg_core_app_secret;
    global $cfg_user_agent;

    $groups = [];

    if (!isset($cfg_core_api) || !isset($cfg_core_app_id) || !isset($cfg_core_app_secret)) {
        return $groups;
    }

    $core_bearer = base64_encode($cfg_core_app_id . ':' . $cfg_core_app_secret);
    $id_query = json_encode(array_values($character_id_array));

    $curl = curl_init($cfg_core_api . '/app/v1/groups');
    curl_setopt_array($curl, [
            CURLOPT_FAILONERROR => true,
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_MAXREDIRS => 5,
            CURLOPT_TIMEOUT => 30,
            CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
            CURLOPT_USERAGENT => $cfg_user_agent,
            CURLOPT_HTTPHEADER => [
                "Authorization: Bearer $core_bearer",
                'Content-type: application/json',
                'Content-length: ' . strlen($id_query)
            ],
            CURLOPT_CUSTOMREQUEST => 'POST',
            CURLOPT_POSTFIELDS => $id_query
        ]
    );
    $response = curl_exec($curl);
    if (!$response) {
        $error = curl_error($curl);
        $_SESSION['error_code'] = 62;
        $_SESSION['error_message'] = 'Failed to retrieve core groups.';
        error_log("Failed to retrieve core groups: $error");

        return false;
    }
    curl_close($curl);

    $characters = json_decode($response, true);
    if (!is_array($characters)) {
        error_log('Neucore returned an invalid response got: ' . print_r($characters, true));
        return false;
    }

    $groupNameMapper = function ($x) {
        return $x['name'];
    };

    foreach ($characters as $character) {
        $character_id = (int)$character['character']['id'];
        if ($character['groups']) {
            $groups[$character_id] = implode(',', array_map($groupNameMapper, $character['groups']));
        } else {
            $groups[$character_id] = '';
        }
    }

    return $groups;
}

/**
 * @return bool
 */
function character_refresh()
{
    global $DB_CONNECTION;

    $stmu =  $DB_CONNECTION->prepare('SELECT character_id FROM user WHERE updated_at < :updated_at');
    $stmu->bindValue(':updated_at', time() - (60 * 60 * 24));
    if (!$stmu->execute()) {
        $err = $stmu->errorInfo();
        echo('FAIL: Failed to retrieve users: ' . $err[0] . ':' . $err[1] . ':' . $err[2] . "\n");
        return false;
    }

    $char_id_list = [];
    while ($row = $stmu->fetch()) {
        $char_id_list[] = (int)$row['character_id'];
    }

    if ($char_id_list) {
        $characters = character_affiliation($char_id_list);
        if (!is_array($characters)) {
            echo 'FAIL: ESI request error.';
            return false;
        }
        $characters_groups = core_groups($char_id_list);
        $stm = $DB_CONNECTION->prepare('UPDATE user
                          SET character_name = :character_name,
                              corporation_id = :corporation_id,
                              corporation_name = :corporation_name,
                              alliance_id = :alliance_id,
                              alliance_name = :alliance_name,
                              mumble_username = :mumble_username,
                              `groups` = :groups,
                              updated_at = :updated_at,
                              mumble_fullname = :mumble_fullname
                          WHERE character_id = :character_id');

        foreach ($characters as $character) {
            echo "Updating: " . $character['character_name'];

            $character_id = (int)$character['character_id'];
            $character_name = (string)$character['character_name'];
            $corporation_id = (int)$character['corporation_id'];
            $corporation_name = (string)$character['corporation_name'];
            $alliance_id = (int)$character['alliance_id'];
            $alliance_name = (string)$character['alliance_name'];
            $mumble_username = toMumbleName($character_name);
            $groups = isset($characters_groups[$character_id]) ? (string)$characters_groups[$character_id] : fetch_fallback_groups($corporation_id, $alliance_id);
            $updated_at = time();
            $mumbleFullName = generateMumbleFullName($character_name, $corporation_id, $alliance_id, $groups);

            $stm->bindValue(':character_id', $character_id);
            $stm->bindValue(':character_name', $character_name);
            $stm->bindValue(':corporation_id', $corporation_id);
            $stm->bindValue(':corporation_name', $corporation_name);
            $stm->bindValue(':alliance_id', $alliance_id);
            $stm->bindValue(':alliance_name', $alliance_name);
            $stm->bindValue(':mumble_username', $mumble_username);
            $stm->bindValue(':groups', $groups);
            $stm->bindValue(':updated_at', $updated_at);
            $stm->bindValue(':mumble_fullname', $mumbleFullName);
            if (!$stm->execute()) {
                $err = $stm->ErrorInfo();
                echo('...failed to update user: ' . $err[0] . ':' . $err[1] . ':' . $err[2] . "\n");
                continue;
            }
            echo "...OK\n";
        }
    }

    return true;
}

$cachedCorporationGroups = [];

/**
 * @param int $corporation_id
 * @param int $alliance_id
 * @return string
 */
function fetch_fallback_groups($corporation_id, $alliance_id)
{
    $corpGroups = fetch_corp_groups($corporation_id);
    $allianceGroups = $alliance_id ? fetch_alliance_groups($alliance_id) : '';
    $corpGroupArray = explode(',', $corpGroups);
    $allianceGroupArray = explode(',', $allianceGroups);
    $groupsArray = array_values(array_unique(array_merge($corpGroupArray, $allianceGroupArray)));

    return trim(implode(',', $groupsArray), ' ,');
}

/**
 * @param int $corporation_id
 * @return string
 */
function fetch_corp_groups($corporation_id)
{
    global $cachedCorporationGroups;
    global $cfg_core_api;
    global $cfg_core_app_id;
    global $cfg_core_app_secret;
    global $cfg_user_agent;

    if (isset($cachedCorporationGroups[$corporation_id])) {
        return $cachedCorporationGroups[$corporation_id];
    }

    if (isset($cfg_core_api) and isset($cfg_core_app_id) and isset($cfg_core_app_secret)) {
        $core_bearer = base64_encode($cfg_core_app_id . ':' . $cfg_core_app_secret);
        $curl = curl_init($cfg_core_api . '/app/v1/corp-groups/' . $corporation_id);
        curl_setopt_array($curl, [
                CURLOPT_FAILONERROR => true,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_MAXREDIRS => 5,
                CURLOPT_TIMEOUT => 30,
                CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
                CURLOPT_USERAGENT => $cfg_user_agent,
                CURLOPT_HTTPHEADER => [
                    "Authorization: Bearer $core_bearer",
                    'Accept: application/json',
                ]
            ]
        );
        $response = curl_exec($curl);
        if (!$response) {
            $error = curl_error($curl);
            $_SESSION['error_code'] = 63;
            $_SESSION['error_message'] = 'Failed to retrieve corporation core groups.';
            error_log("Failed to retrieve corporation core groups: $error");

            return '';
        }
        curl_close($curl);
        $groupsFull = json_decode($response, true);
        $groupString = trim(array_reduce($groupsFull, function ($groupString, $groupInfo) {
            $groupString .= $groupInfo['name'] . ',';

            return $groupString;
        }, ''), ', ');

        $cachedCorporationGroups[$corporation_id] = $groupString;

        return $groupString;
    }

    return '';
}

/**
 * @param int $alliance_id
 * @return string
 */
function fetch_alliance_groups($alliance_id)
{
    global $cachedAllianceGroups;
    global $cfg_core_api;
    global $cfg_core_app_id;
    global $cfg_core_app_secret;
    global $cfg_user_agent;

    if (isset($cachedAllianceGroups[$alliance_id])) {
        return $cachedAllianceGroups[$alliance_id];
    }

    if (isset($cfg_core_api) and isset($cfg_core_app_id) and isset($cfg_core_app_secret)) {
        $core_bearer = base64_encode($cfg_core_app_id . ':' . $cfg_core_app_secret);
        $curl = curl_init($cfg_core_api . '/app/v1/alliance-groups/' . $alliance_id);
        curl_setopt_array($curl, [
                CURLOPT_FAILONERROR => true,
                CURLOPT_RETURNTRANSFER => true,
                CURLOPT_MAXREDIRS => 5,
                CURLOPT_TIMEOUT => 30,
                CURLOPT_HTTP_VERSION => CURL_HTTP_VERSION_1_1,
                CURLOPT_USERAGENT => $cfg_user_agent,
                CURLOPT_HTTPHEADER => [
                    "Authorization: Bearer $core_bearer",
                    'Accept: application/json',
                ]
            ]
        );
        $response = curl_exec($curl);
        if (!$response) {
            $error = curl_error($curl);
            $_SESSION['error_code'] = 63;
            $_SESSION['error_message'] = 'Failed to retrieve alliance core groups.';
            error_log("Failed to retrieve alliance core groups: $error");

            return '';
        }
        curl_close($curl);
        $groupsFull = json_decode($response, true);
        $groupString = trim(array_reduce($groupsFull, function ($groupString, $groupInfo) {
            $groupString .= $groupInfo['name'] . ',';

            return $groupString;
        }, ''), ', ');

        $cachedAllianceGroups[$alliance_id] = $groupString;

        return $groupString;
    }

    return '';
}

/**
 * Gets missing tickers.
 * @param int $limit
 */
function fetchTicker($limit = 10)
{
    global $DB_CONNECTION;

    // get missing ticker corp/alli IDs
    $stm = $DB_CONNECTION->prepare('
        SELECT "corporation" AS type, u.corporation_id AS id
        FROM user AS u
        LEFT JOIN ticker AS t ON t.filter = CONCAT("corporation", "-", u.corporation_id)
        WHERE t.text IS NULL
        UNION
        SELECT "alliance" AS type, u.alliance_id AS id
        FROM user AS u
        LEFT JOIN ticker AS t ON t.filter = CONCAT("alliance", "-", u.alliance_id)
        WHERE t.text IS NULL AND u.alliance_id IS NOT NULL AND u.alliance_id > 0
        LIMIT ' . intval($limit));
    if (!$stm->execute()) {
        error_log('SQL failure: getting corp/alli IDs in fetchTicker()');

        return;
    }
    $missingIds = $stm->fetchAll(PDO::FETCH_ASSOC);
    addMissingTickersToDatabase($missingIds);
}

/**
 * @param array $missingTickers
 * @return bool
 */
function addMissingTickersToDatabase($missingTickers) 
{
    global $DB_CONNECTION;

    // query ESI
    $tickers = [];
    foreach ($missingTickers as $missingTicker) {
        $tickerExists = findTicker($missingTicker['id'], $missingTicker['type']);
        if ($tickerExists !== false) {
            // Already exists
            continue;
        }

        $esiHost = 'https://esi.evetech.net';
        $dataSource = 'datasource=tranquility';
        if ($missingTicker['type'] === 'alliance') {
            $route = '/latest/alliances/';
        } else {
            $route = '/latest/corporations/';
        }
        $result = file_get_contents($esiHost . $route . $missingTicker['id'] . '/?' . $dataSource);
        $json = json_decode($result); // $result may be false from file_get_contents()
        if ($json === null || $json === false) {
            error_log('ESI failure: getting corp/alliance ticker fetchTicker()');
            continue;
        }
        $tickers[] = [
            'type' => $missingTicker['type'],
            'id' => $missingTicker['id'],
            'ticker' => $json->ticker,
        ];
    }

    // add to db
    foreach ($tickers as $ticker) {
        $stm = $DB_CONNECTION->prepare('INSERT INTO ticker (filter, text) VALUES (:filter, :text) ON DUPLICATE KEY UPDATE text = :text');
        $stm->bindValue(':filter', $ticker['type'] . '-' . $ticker['id']);
        $stm->bindValue(':text', $ticker['ticker']);
        $stm->execute();
    }

    return true;
}

function findTicker($id, $type = 'corporation')
{
    global $DB_CONNECTION;

    $stm = $DB_CONNECTION->prepare('SELECT * FROM ticker WHERE filter = :filter');
    $stm->bindValue(':filter', $type . '-' . $id);
    if (!$stm->execute()) {
        $_SESSION['error_code'] = 97;
        $_SESSION['error_message'] = 'Failed to query database for ticker.';
        $arr = $stm->ErrorInfo();
        error_log('SQL failure:' . $arr[0] . ':' . $arr[1] . ':' . $arr[2]);
        return false;
    }

    return $stm->fetch();
}

function generateMumbleFullName($character_name, $corporation_id, $alliance_id, $groups)
{
    global $cfg_groups_to_tags;

    $groupsArray = explode(',', $groups);

    $corporationTicker = findTicker($corporation_id);

    $result = $character_name;

    $result .= $corporationTicker ? (' [' . $corporationTicker['text'] . ']') : '';

    $tag = '';

    foreach ($cfg_groups_to_tags as $group => $assignedTag) {
        if (in_array($group, $groupsArray)) {
            $tag = $assignedTag;
            // First one wins for now
            break;
        }
    }

    $result .= $tag ? (' (' . $tag . ')') : '';
    return $result;
}

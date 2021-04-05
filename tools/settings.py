def init():
    global alg_types
    alg_types = ['cipher', 'md', 'ke']

    global alg_labels
    alg_labels = {'cipher': ['encrypt', 'decrypt'], 'md': ['hash', 'verify'], 'ke': ['server', 'client']}

    global alg_parser_opts
    alg_parser_opts = {'cipher': [3, 'msglen', 'operation'], 'md': [3, 'msglen', 'operation'], 'ke': [2, 'keylen', 'endpoint']}

    global serv_types
    serv_types = ['conf', 'int', 'auth', 'pfs']

    global serv_labels
    serv_labels = {'conf': ['encrypt', 'decrypt'], 'int': ['hash', 'verify'], 'auth': ['server', 'client'], 'pfs': ['server', 'client']}

    global serv_to_alg
    serv_to_alg = {'conf': 'cipher', 'int': 'md', 'auth': 'ke', 'pfs': 'ke'}

    global security_lvls
    security_lvls = ['80', '112', '128', '192', '256']

    global keylen_to_sec_lvl
    keylen_to_sec_lvl = {
        '10': 0, '14': 1, '16': 2, '24': 3, '32': 4,
        '1024': 0, '2048': 1, '3072': 2, '4096': 3, '8192': 4,
        '192': 0, '224': 1, '256': 2, '384': 3, '521': 4
    }

    global ke_alg_operations
    ke_alg_operations = {
        'PSK': ['parse_client_psk_identity', 'parse_server_psk_hint', 'psk_derive_premaster'],
        'RSA': ['rsa_encrypt', 'rsa_decrypt', 'rsa_sign_with_sha256', 'rsa_verify_with_sha256',
                'rsa_sign_with_sha512', 'rsa_verify_with_sha512'],
        'ECDSA': ['ecdsa_sign_with_sha256', 'ecdsa_verify_with_sha256', 'ecdsa_sign_with_sha512', 'ecdsa_verify_with_sha512'],
        'DHE': ['dhm_set_group', 'dhm_make_params', 'parse_server_dh_params',
                'dhm_make_public', 'parse_client_dh_public', 'dhm_calc_secret'],
        'ECDH': ['get_ecdh_params_from_cert', 'ecdh_make_public', 'ecdh_read_public', 'ecdh_calc_secret'],
        'ECDHE': ['ecdh_setup', 'ecdh_make_params', 'parse_server_ecdh_params']
    }

    global strlen
    strlen = 55
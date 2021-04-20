def init():
    global alg_types
    alg_types = ['cipher', 'md', 'ke']

    global alg_labels
    alg_labels = {
        'cipher': ['encrypt', 'decrypt'],
        'md': ['hash', 'verify'],
        'ke': ['server', 'client']
    }

    global alg_parser_opts
    alg_parser_opts = {
        'cipher': [3, 'msglen', 'operation'],
        'md': [3, 'msglen', 'operation'],
        'ke': [2, 'keylen', 'endpoint']
    }

    global serv_types
    serv_types = ['conf', 'int', 'auth', 'ke', 'pfs', 'hs']

    global serv_labels
    serv_labels = {
        'conf': ['encrypt', 'decrypt'], 'int': ['hash', 'verify'],
        'auth': ['server', 'client'], 'ke': ['all'], 'pfs': ['all'], 'hs': ['all']
    }

    global serv_to_alg
    serv_to_alg = {
        'conf': 'cipher', 'int': 'md', 'auth': 'ke',
        'ke': 'ke', 'pfs': 'ke', 'hs': 'ke'
    }

    global sec_str
    sec_str = ['80', '112', '128', '192', '256']

    global keylen_to_sec_str
    keylen_to_sec_str = {
        '10': 0, '14': 1, '16': 2, '24': 3, '32': 4,
        '1024': 0, '2048': 1, '3072': 2, '4096': 3, '8192': 4,
        '192': 0, '224': 1, '256': 2, '384': 3, '521': 4
    }

    global ke_operations_per_service
    ke_operations_per_service = {
        'auth': {
            'PSK': ['parse_client_psk_identity', 'parse_server_psk_hint'],
            'RSA': ['rsa_encrypt', 'rsa_decrypt', 'rsa_sign_with_sha256',
                    'rsa_verify_with_sha256', 'rsa_sign_with_sha512', 'rsa_verify_with_sha512'],
            'ECDSA': ['ecdsa_sign_with_sha256', 'ecdsa_verify_with_sha256', 'ecdsa_sign_with_sha512', 'ecdsa_verify_with_sha512']
        },
        'ke': {
            'PSK': ['psk_derive_premaster'],
            'DHE': ['dhm_make_public', 'parse_client_dh_public', 'dhm_calc_secret'],
            'ECDH': ['get_ecdh_params_from_cert', 'ecdh_make_public', 'ecdh_read_public', 'ecdh_calc_secret'],
            'ECDHE': ['ecdh_make_public', 'ecdh_read_public', 'ecdh_calc_secret']
        },
        'pfs': {
            'DHE': ['dhm_set_group', 'dhm_make_params', 'parse_server_dh_params'],
            'ECDHE': ['ecdh_setup', 'ecdh_make_params', 'parse_server_ecdh_params']
        }
    }

    global strlen
    strlen = 55
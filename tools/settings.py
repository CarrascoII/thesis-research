def init():
    global alg_types
    alg_types = ['cipher', 'md', 'ke']

    global alg_labels
    alg_labels = {
        'cipher': ['encrypt', 'decrypt'], 'md': ['hash', 'verify'],
        'ke': ['server', 'client'], 'handshake': ['server', 'client']
    }

    global alg_parser_opts
    alg_parser_opts = {
        'cipher': [2, 'msglen', 'operation'], 'md': [2, 'msglen', 'operation'],
        'ke': [3, 'sec_lvl'], 'handshake': [2, 'sec_lvl']
    }

    global serv_types
    serv_types = ['conf', 'int', 'auth', 'ke', 'pfs']

    global hs_servs
    hs_servs = ['auth', 'ke', 'pfs']

    global serv_fullname
    serv_fullname = {
        'conf': 'Confidentiality',
        'int': 'Integrity',
        'auth': 'Authentication',
        'ke': 'Key Establishment',
        'pfs': 'Perfect Forward Secrecy',
        'hs': 'Handshake'
    }

    global serv_labels
    serv_labels = {
        'conf': ['encrypt', 'decrypt'], 'int': ['hash', 'verify'], 'auth': ['server', 'client'],
        'ke': ['server', 'client'], 'pfs': ['server', 'client'], 'hs': ['server', 'client']
    }

    global serv_to_alg
    serv_to_alg = {
        'conf': 'cipher', 'int': 'md', 'auth': 'ke',
        'ke': 'ke', 'pfs': 'ke'
    }

    global sec_str
    sec_str = ['80', '112', '128', '192', '256']

    global keylen_to_sec_str
    keylen_to_sec_str = {
        '10': 0, '14': 1, '16': 2, '24': 3, '32': 4,
        '1024': 0, '2048': 1, '3072': 2, '4096': 3, '8192': 4,
        '192': 0, '224': 1, '256': 2, '384': 3, '521': 4
    }

    # global ke_operations
    # ke_operations = {
    #     'PSK': ['parse_client_psk_identity', 'parse_server_psk_hint', 'psk_derive_premaster'],
    #     'RSA': ['rsa_encrypt', 'rsa_decrypt'],
    #     'RSA-SHA256': ['rsa_sign_with_sha256', 'rsa_verify_with_sha256'],
    #     'RSA-SHA512': ['rsa_sign_with_sha512', 'rsa_verify_with_sha512'],
    #     'ECDSA-SHA256': ['ecdsa_sign_with_sha256', 'ecdsa_verify_with_sha256'],
    #     'ECDSA-SHA512': ['ecdsa_sign_with_sha512', 'ecdsa_verify_with_sha512'],
    #     'DHE': ['dhm_set_group', 'dhm_make_params', 'parse_server_dh_params',
    #             'dhm_make_public', 'parse_client_dh_public', 'dhm_calc_secret'],
    #     'ECDH': ['get_ecdh_params_from_cert', 'ecdh_make_public', 'ecdh_read_public', 'ecdh_calc_secret'],
    #     'ECDHE': ['ecdh_setup', 'ecdh_make_params', 'parse_server_ecdh_params',
    #                 'ecdh_make_public', 'ecdh_read_public', 'ecdh_calc_secret'],
    #     'SHA256': ['sha256_hash_extended_master_secret', 'sha256_hash_master_secret', 'sha256_hash_key_expansion'],
    #     'SHA384': ['sha384_hash_extended_master_secret', 'sha384_hash_master_secret', 'sha384_hash_key_expansion']
    # }

    # global ke_operations_per_service
    # ke_operations_per_service = {
    #     'auth': {
    #         'PSK': ['parse_client_psk_identity', 'parse_server_psk_hint'],
    #         'RSA': ['rsa_encrypt', 'rsa_decrypt'],
    #         'RSA-SHA256': ['rsa_sign_with_sha256', 'rsa_verify_with_sha256'],
    #         'RSA-SHA512': ['rsa_sign_with_sha512', 'rsa_verify_with_sha512'],
    #         'ECDSA-SHA256': ['ecdsa_sign_with_sha256', 'ecdsa_verify_with_sha256'],
    #         'ECDSA-SHA512': ['ecdsa_sign_with_sha512', 'ecdsa_verify_with_sha512']
    #     },
    #     'ke': {
    #         'PSK': ['psk_derive_premaster'],
    #         'DHE': ['dhm_make_public', 'parse_client_dh_public', 'dhm_calc_secret'],
    #         'ECDH': ['get_ecdh_params_from_cert', 'ecdh_make_public', 'ecdh_read_public', 'ecdh_calc_secret'],
    #         'ECDHE': ['ecdh_make_public', 'ecdh_read_public', 'ecdh_calc_secret'],
    #         'SHA256': ['sha256_hash_extended_master_secret', 'sha256_hash_master_secret', 'sha256_hash_key_expansion'],
    #         'SHA384': ['sha384_hash_extended_master_secret', 'sha384_hash_master_secret', 'sha384_hash_key_expansion']
    #     },
    #     'pfs': {
    #         'DHE': ['dhm_set_group', 'dhm_make_params', 'parse_server_dh_params'],
    #         'ECDHE': ['ecdh_setup', 'ecdh_make_params', 'parse_server_ecdh_params']
    #     }
    # }

    global ke_operations
    ke_operations = {
        'PSK': ['parse_client_psk_identity', 'parse_server_psk_hint', 'psk_derive_premaster'],
        'RSA': ['rsa_encrypt', 'rsa_decrypt', 'rsa_sign_with_sha256', 'rsa_verify_with_sha256', 'rsa_sign_with_sha512', 'rsa_verify_with_sha512'],
        'ECDSA': ['ecdsa_sign_with_sha256', 'ecdsa_verify_with_sha256', 'ecdsa_sign_with_sha512', 'ecdsa_verify_with_sha512'],
        'DHE': ['dhm_set_group', 'dhm_make_params', 'parse_server_dh_params',
                'dhm_make_public', 'parse_client_dh_public', 'dhm_calc_secret'],
        'ECDH': ['get_ecdh_params_from_cert', 'ecdh_make_public', 'ecdh_read_public', 'ecdh_calc_secret'],
        'ECDHE': ['ecdh_setup', 'ecdh_make_params', 'parse_server_ecdh_params',
                    'ecdh_make_public', 'ecdh_read_public', 'ecdh_calc_secret'],
        'SHA256': ['sha256_hash_extended_master_secret', 'sha256_hash_master_secret', 'sha256_hash_key_expansion'],
        'SHA384': ['sha384_hash_extended_master_secret', 'sha384_hash_master_secret', 'sha384_hash_key_expansion']
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
            'ECDHE': ['ecdh_make_public', 'ecdh_read_public', 'ecdh_calc_secret'],
            'SHA256': ['sha256_hash_extended_master_secret', 'sha256_hash_master_secret', 'sha256_hash_key_expansion'],
            'SHA384': ['sha384_hash_extended_master_secret', 'sha384_hash_master_secret', 'sha384_hash_key_expansion']
        },
        'pfs': {
            'DHE': ['dhm_set_group', 'dhm_make_params', 'parse_server_dh_params'],
            'ECDHE': ['ecdh_setup', 'ecdh_make_params', 'parse_server_ecdh_params']
        }
    }

    global strlen
    strlen = 55
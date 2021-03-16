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
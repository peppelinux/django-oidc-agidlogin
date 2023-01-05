def issuer_prefixed_sub(user_info:dict,
                        client_conf:dict,
                        data:dict=None,
                        kwargs:dict={}):
    return f"{data['issuer_id']}{kwargs.get('sep', '__')}{user_info['sub']}"

def is_digital_identity(user_info:dict,
                        client_conf:dict,
                        data:dict=None,
                        kwargs:dict={}):

    if "SPID:TINIT-" in user_info['sub'] or "CIE:TINIT-" in user_info['sub']:
        return "Sì"

def codice_fiscale(user_info:dict,
                   client_conf:dict,
                   data:dict=None,
                   kwargs:dict={}):
    if "fiscalNumber" in user_info:
        return user_info["fiscalNumber"]
        

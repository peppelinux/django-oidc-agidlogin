from django.conf import settings

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
        return "si"

def codice_fiscale(user_info:dict,
                   client_conf:dict,
                   data:dict=None,
                   kwargs:dict={}):
    if "fiscalNumber" in user_info:
        return f'TINIT-{user_info["fiscalNumber"]}'

def is_agid_staff(user_info:dict,
                  client_conf:dict,
                  data:dict=None,
                  kwargs:dict={}):
    if "Microsoft:" in user_info['sub'] and "@agid.gov.it" in user_info['sub']:
        return "si"

def is_digital_identity(user_info:dict,
                        client_conf:dict,
                        data:dict=None,
                        kwargs:dict={}):
    if "SPID:TINIT-" in user_info['sub'] or "CIE:TINIT-" in user_info['sub']:
        return "si"
        
def user_is_employee(user):
    if not user: return False
    if getattr(settings, 'EMPLOYEE_ATTRIBUTE_NAME', False):
        attr = getattr(user, settings.EMPLOYEE_ATTRIBUTE_NAME)
        if callable(attr): return attr()
        else: return attr
    return False

def user_is_in_organization(user):
    if not user: return False
    if getattr(settings, 'USER_ATTRIBUTE_NAME', False):
        attr = getattr(user, settings.USER_ATTRIBUTE_NAME)
        if callable(attr): return attr()
        else: return attr
    return False

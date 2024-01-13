import random

import frappe
import jwt
from frappe import _
from frappe.auth import LoginManager
from frappe.utils import cint, get_url, get_datetime
from frappe.utils.password import check_password, passlibctx, update_password
from datetime import datetime,timedelta
import json



def get_linked_user(id_type, id):
  """
  Returns the user associated with the details
  :param id_type: either 'mobile' or 'email'
  :param id: the email/mobile
  """
  if id_type not in ("mobile", "sms", "email"):
    frappe.throw(f"Invalid id_type: {id_type}")

  if id_type in ("mobile", "sms"):
    id_type = "mobaile_no"

  return frappe.db.get_value("User", {id_type: id})





@frappe.whitelist(allow_guest=True)
def get_token(user, pwd, expires_in=3600, expire_on=None, device=None):
  """
  Get the JWT Token
  :param user: The user in ctx
  :param pwd: Pwd to auth
  :param expires_in: number of seconds till expiry
  :param expire_on: yyyy-mm-dd HH:mm:ss to specify the expiry (deprecated)
  :param device: The device in ctx
  """
  if not frappe.db.exists("User", user):
    raise frappe.ValidationError(_("Invalide User"))

  from frappe.sessions import clear_sessions
  login = LoginManager()
  login.check_if_enabled(user)
  if not check_password(user, pwd):
    login.fail('Incorrect password', user=user)
  login.login_as(user)
  login.resume = False
  login.run_trigger('on_session_creation')
  _expires_in = 3600
  if cint(expires_in):
    _expires_in = cint(expires_in)
  elif expire_on:
    _expires_in = (get_datetime(expire_on) - get_datetime()).total_seconds()


  token = get_bearer_token(
    user=user,
    expires_in=_expires_in
  )
  frappe.local.response["token"] = token["access_token"]
  frappe.local.response.update(token)


def get_oath_client():
  client = frappe.db.get_value("OAuth Client", {})
  if not client:
    # Make one auto
    client = frappe.get_doc(frappe._dict(
        doctype="OAuth Client",
        app_name="default",
        scopes="all openid",
        redirect_urls=get_url(),
        default_redirect_uri=get_url(),
        grant_type="Implicit",
        response_type="Token"
    ))
    client.insert(ignore_permissions=True)
  else:
    client = frappe.get_doc("OAuth Client", client)

  return client


def get_bearer_token(user, expires_in=3600):
  import hashlib
  import jwt
  import frappe.oauth
  from oauthlib.oauth2.rfc6749.tokens import random_token_generator, OAuth2Token

  client = get_oath_client()
  token = frappe._dict({
      'access_token': random_token_generator(None),
      'expires_in': 30*24*60*60,
      'token_type': 'Bearer',
      'scopes': client.scopes,
      'refresh_token': random_token_generator(None)
  })
  

  # ID Token
  id_token_header = {
      "typ": "jwt",
      "alg": "HS256"
  }
  id_token = {
      "aud": frappe.conf.get("ring_aud"),
      "exp":  datetime.utcnow()+timedelta(seconds=30*24*60*60),
      "sub": json.dumps({"token":token["access_token"],"user":user}),
      "iss": "frappe_server_url",
      "at_hash": frappe.oauth.calculate_at_hash(token.access_token, hashlib.sha256),
      "UID":user 
  }
  id_token_encoded = jwt.encode(
      id_token, frappe.conf.get("jwt_client_secret"), algorithm='HS256', headers=id_token_header)
  id_token_encoded = frappe.safe_decode(id_token_encoded)
  token.id_token = id_token_encoded
  frappe.flags.jwt = id_token_encoded
  bearer_token = frappe.new_doc("OAuth Bearer Token")
  bearer_token.client = client.name
  bearer_token.scopes = token['scopes']
  bearer_token.access_token = token['access_token']
  bearer_token.refresh_token = token.get('refresh_token')
  bearer_token.expires_in = token['expires_in'] or 3600
  bearer_token.user = user
  bearer_token.save(ignore_permissions=True)
  frappe.db.commit()
  frappe.log_error("token",token)
  return token


@frappe.whitelist()
def get_jwt_token():
  """
  Get jwt token for the active user
  """
  return get_bearer_token(
      user=frappe.session.user, expires_in=86400
  )["access_token"]

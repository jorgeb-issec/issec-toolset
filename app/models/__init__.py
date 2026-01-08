# import models for flask migrate to discover
from .user import User
from .equipo import Equipo
from .policy import Policy
from .config_history import ConfigHistory
from .log_entry import LogEntry, LogImportSession, SecurityRecommendation
from .site import Site
from .vdom import VDOM
from .history import PolicyHistory

# v1.3.0 - New models
from .interface import Interface, InterfaceHistory
from .address_object import AddressObject
from .service_object import ServiceObject
from .vpn_tunnel import VPNTunnel
from .policy_mappings import PolicyInterfaceMapping, PolicyAddressMapping, PolicyServiceMapping
from .security_alerts import AllowedAccessAlert, ServerExposure
from .vdom_history import VDOMHistory
from .saved_report import SavedReport

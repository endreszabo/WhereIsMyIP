#!/usr/bin/python

import re
from socket import inet_ntoa
from struct import pack
from netaddr import IPNetwork, IPAddress
from subprocess import Popen, PIPE

class IPRoute(object):
	network=None
	gateway=None
	interface=None
	name=None
	def __init__(self, network, netmask, gateway, interface, name=None):
		self.network=IPNetwork("%s/%s" % (network, netmask))
		self.gateway=IPAddress(gateway)
		self.interface=interface
		self.name=name
	def is_in(self,address): 
		return IPAddress(address) in IPNetwork
	def __iter__(self):
		return self.network.__iter__()
	def __str__(self):
		if self.name:
			return "%s via %s on %s, called %s" % (self.network, self.gateway, self.interface, self.name)
		else:
			return "%s via %s on %s" % (self.network, self.gateway, self.interface)
	def __repr__(self):
		return "%s('%s')" % (self.__class__.__name__, self)
	def get_name(self):
		return self.name

class Host(object):
	hostname=''
	default_gw=None
	routes=[]
	def __init__(self,hostname):
		self.hostname=hostname
	def add_network(self, network, netmask, gateway, interface):
		self.routes.append(IPRoute(network, netmask, gateway, interface))
	def add_default_gw(self,address):
		if not self.default_gw:
			self.default_gw=address
		else:
			raise MultipleDefaultGateways('foo')
	def has_route(self, address):
		if not self.routes:
			raise HostHasNoRoutes
		for network in self.routes:
			if address in network[0]:
				return 1
		return 0
	def where_it_routes(self, address):
		if not self.routes:
			raise HostHasNoRoutes
		results=[]
		for route in self.routes:
			if address in route:
				results.append(route)
		return results
	

def ip_hex_to_dotted(address):
	return inet_ntoa(pack("L",int(address,16)))

p=Popen(['ssh','localhost','cat /proc/net/route'],
	stdin=PIPE,
	stdout=PIPE,
	stderr=PIPE,
	)
pattern=re.compile(r"^(?P<iface>[\S]+)\t(?P<network>[0-9A-F]{8})\t(?P<gateway>[0-9A-F]{8})\t(?P<flags>[0-9]+)(?:\t[0-9]+){3}\t(?P<netmask>[0-9A-F]{8})",re.M)
host=Host('localhost')
for iface in pattern.finditer(p.communicate()[0]):
	route_data=iface.groupdict()
	for data in ['netmask','gateway','network']:
		route_data[data]=ip_hex_to_dotted(route_data[data])
	if route_data['netmask'] == '0.0.0.0' and route_data['network'] == '0.0.0.0':
		host.add_default_gw(route_data['gateway'])
	else:#if route_data['gateway'] == '0.0.0.0':
		host.add_network(route_data['network'],route_data['netmask'], route_data['gateway'], route_data['iface'])
	print route_data
print repr(host.default_gw)
print repr(host.routes)
print host.where_it_routes(IPAddress('192.0.2.5'))


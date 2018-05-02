import sys, os
import struct
import argparse
import ConfigParser
try:
	import sqlite3
except:
	print "[!] Please install python-sqlite3 extension."
	sys.exit(0)

"""
ldapsearch -h <ip> -x -D <username> -w <password> -b <base DN> -E pr=1000/noprompt -o ldif-wrap=no
"""

__prog_name__ = 'binder'

def ldif_to_dict(ldif):
	"""parses an ldif export into a python dictionary"""
	
	ldap = {}
	with open(ldif) as file:
		for line in file:
			line = line.strip()

			if line.startswith('#') or not len(line):
				continue

			if line.startswith('dn: '):
				key = line[4:]
				ldap[key] = {'dn': key}

			else:
				try:
					attr, val = line.split(': ', 1)
					attr = attr.strip(':')
				except:
					pass
				if attr in ldap[key]:

					if not isinstance(ldap[key][attr], list):
						ldap[key][attr] = [ldap[key][attr]]
					
					ldap[key][attr].append(val)
				
				else:
					ldap[key][attr] = val

	return ldap

# Function copied from ADoffline
def get_string_sid_from_binary_sid(base64string):
	binarysid = base64string.decode('base64')
	version = struct.unpack('B', binarysid[0])[0]
	assert version == 1, version
	length = struct.unpack('B', binarysid[1])[0]
	authority = struct.unpack('>Q', '\x00\x00' + binarysid[2:8])[0]
	string = 'S-%d-%d' % (version, authority)
	binarysid = binarysid[8:]
	assert len(binarysid) == 4 * length
	for i in xrange(length):
		value = struct.unpack('<L', binarysid[4*i:4*(i+1)])[0]
		string += '-%d' % (value)
	return (string, value)

def get_confirmation(text):
	try:
		res = raw_input(text +' (y/[n]): ').strip()
	except KeyboardInterrupt:
		print
		return False

	return res.lower() == 'y'

if __name__ == '__main__':

	if len(sys.argv) == 1:
		sys.argv.append('--help')

	parser = argparse.ArgumentParser(description='%s LDIF import' % __prog_name__)

	parser.add_argument(
		'file',
		action='store',
		metavar='<ldif_filename>',
		type=argparse.FileType('r'),
		help='File name to read LDAP export from.',
		default=False)

	cfg = parser.parse_args()
	cfg.config_file  = os.path.join(os.path.expanduser('~'), '.%s' % __prog_name__)

	CP = ConfigParser.ConfigParser()
	CP.read(cfg.config_file)
	
	try:
		cfg.project_dir     = os.path.expanduser(CP.get('core', 'PROJECTS_PATH').strip())
		cfg.current_project = CP.get('core', 'CURRENT_PROJECT').strip()

	except ConfigParser.NoOptionError:
		sys.exit("[!] Error: some fields are missing from the configuration file.")

	if not get_confirmation('Do you really want to update the database for the "%s" project?' % cfg.current_project):
		sys.exit(1)

	cfg.db_filename     = '%s.db' % __prog_name__
	cfg.base_dir        = os.path.join(cfg.project_dir, cfg.current_project)
	cfg.binder_dir      = os.path.join(cfg.base_dir, '.'+__prog_name__)
	cfg.database        = os.path.join(cfg.binder_dir, cfg.db_filename)

	if not os.path.exists(cfg.database):
		sys.exit("[!] Error: database not found for this project. Please start the project first.")

	cfg.cursor = sqlite3.connect(cfg.database)
	cfg.cursor.text_factory = str

	cfg.domain_list = {}
	res = cfg.cursor.execute("SELECT id, `domain`, `fqdn` FROM domains").fetchall()
	for row in res:
		cfg.domain_list[row[0]] = (row[1], row[2])

	print "[*] Parsing input file..."
	ldif = ldif_to_dict(cfg.file.name)

	domains = []
	groups = []
	users = []
	members = []

	print "[*] Extracting domains..."
	for k, v in ldif.iteritems():

		# domain
		if 'objectClass' in v and v['objectClass'] == ['top', 'domain', 'domainDNS']:
			dom_id = max(cfg.domain_list.keys()) + 1 if len(cfg.domain_list) else 1
			dom_short = v['name'].upper()
			dom_long = '.'.join(v['dn'][3:].split(',DC=')).upper()

			for k, v in cfg.domain_list.iteritems():
				if v[1] == dom_long:
					dom_short = v[0]
					dom_id = k

			domains.append((dom_id, dom_short, dom_long))
			break

	print "[*] Extracting users and groups..."
	group_members = {}
	group_to_sid = {}
	user_to_sid = {}
	for k, v in ldif.iteritems():

		# group
		if 'objectClass' in v and v['objectClass'] == ['top', 'group']:
			dn = v['dn']
			name = v['name']

			sid = get_string_sid_from_binary_sid(v['objectSid'])[1]

			try:
				group_to_sid[dn] = sid
				groups.append((sid, dom_id, name))
				group_members[sid] = v['member'] if 'member' in v else []
			except:
				print "exp1"

		# user
		if 'objectClass' in v and v['objectClass'] == ['top', 'person', 'organizationalPerson', 'user']:
			dn = v['dn']
			name = v['name']
			username = v['sAMAccountName']
			descr = v['description'] if 'description' in v else None
			
			sid = get_string_sid_from_binary_sid(v['objectSid'])[1]
	
			try:
				user_to_sid[dn] = sid
				users.append((sid, dom_id, username, None, None, None, name, descr))
			except:
				print "exp2."

	print "[*] Resolving group memberships..."
	for group_id, v in group_members.iteritems():

		if not isinstance(v, list):
			v = [v]

		for m in v:
			if m in group_to_sid:
				account_id = group_to_sid[m]
				is_group = 1
			elif m in user_to_sid:
				account_id = user_to_sid[m]
				is_group = 0
			else:
				continue

			idx = hex(int('%d%d%d' % (dom_id, account_id, group_id)))[2:]
			members.append((idx, dom_id, account_id, group_id, is_group))

	print "[*] Updating database..."

	res_u = cfg.cursor.executemany("INSERT OR REPLACE INTO domains (id, domain, fqdn) VALUES (?, ?, ?)", domains)
	print "[+] %d domains updated." % res_u.rowcount

	res_u = cfg.cursor.executemany("INSERT OR REPLACE INTO domain_accounts (rid, domain_id, username, password, lm_hash, nt_hash, name, descr) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", users)
	print "[+] %d user accounts updated." % res_u.rowcount

	res_g = cfg.cursor.executemany("INSERT OR REPLACE INTO domain_groups (rid, domain_id, name) VALUES(?, ?, ?)", groups)
	print "[+] %d unique groups updated." % res_g.rowcount

	res_m = cfg.cursor.executemany("INSERT OR REPLACE INTO group_members (idx, domain_id, account_id, group_id, is_group) VALUES(?, ?, ?, ?, ?)", members)
	print "[+] %d group memberships updated." % res_m.rowcount

	cfg.cursor.commit()
	print "[*] Done."

#!/usr/bin/env python
import sys
import os
import subprocess
import socket
import datetime
import shlex
import re
import hashlib
import argparse
import itertools
import ConfigParser
from random import choice

try:
	import sqlite3
except:
	print "[!] Please install python-sqlite3 extension."
	sys.exit(0)

__version__ = 0.4
__prog_name__ = 'binder'

def main():

	parser = argparse.ArgumentParser(description='%s version %f' % (__prog_name__, __version__))
	exclusive = parser.add_mutually_exclusive_group()

	exclusive.add_argument(
		'-s', '--start',
		action='store',
		metavar='<project_name>',
		dest='start',
		help='Start a new project or resume an existing project',
		default=False)

	exclusive.add_argument(
		'-y', '--screenshot',
		action='store_true',
		help='Take a screenshot and save it in the project folder',
		default=False)

	parser.add_argument('-d', '--domain',
		action='store',
		metavar='<domain_name>',
		dest='setdomain',
		help='Limit all actions to this domain. (i.e. when querying information)',
		default=False)

	exclusive.add_argument(
		'-x', '--update_hashes',
		action='store',
		dest='update_hashes',
		metavar='<filename>',
		type=argparse.FileType('r'),
		help='Load creds into db from dump file. Provide pwdump-style file',
		default=False)

	exclusive.add_argument(
		'-a', '--update_accounts',
		action='store',
		dest='update_accounts',
		metavar='<filename>',
		type=argparse.FileType('r'),
		help='Load user and parser info into db. Provide enum4linux output file',
		default=False)

	exclusive.add_argument('-c', '--crack',
		action='store',
		dest='crack',
		metavar='<levels>',
		type=int,
		nargs='*',
		help='Run multiple password cracking attacks. Pass a space-separated list of levels. Levels: 1: Local db, 2: single, 3: dictionaries/rules, 4: masks, 5: markov, 6: brute-force. Default: 1 2',
		default=False)

	exclusive.add_argument(
		'-g', '--group',
		action='store',
		metavar='<group_name>',
		help='Return group members with usernames and passwords (if cracked)',
		default=False)

	exclusive.add_argument('-f', '--flush',
		action='store_true',
		help='Delete user and parser data from db',
		default=False)

	exclusive.add_argument('-p', '--passwords',
		action='store_true',
		dest='getpasswords',
		help='Display all cracked passwords',
		default=False)

	exclusive.add_argument('-z', '--getpass',
		action='store',
		dest='getpass',
		metavar='<username>',
		help='Output the user\'s password or otherwise NT hash',
		default=False)

	exclusive.add_argument('-u', '--user',
		action='store',
		dest='getuser',
		metavar='<username>',
		help='Display all the information about a user.',
		default=False)

	parser.add_argument('-o', '--report',
		action='store_true',
		help='Generate a report',
		default=False)

	parser.add_argument('-v', '--verbose',
		action='store_true',
		help='Enable debug messages',
		default=False)

	global cfg
	cfg = parser.parse_args()
	cfg.prog_name = __prog_name__
	cfg.config_file  = os.path.join(os.path.expanduser('~'), '.%s' % cfg.prog_name)

	# Handle first run
	if not os.path.exists(cfg.config_file):
		
		sample = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'config.sample')
		default_conf = open(sample).read()
		open(cfg.config_file, 'w').write(default_conf)

		print "[*] Sample configuration file copied to %s" % cfg.config_file
		print "[*] Please edit the file and run this program again."
		sys.exit(0)

	# Config File parsing
	CP = ConfigParser.ConfigParser()
	CP.read(cfg.config_file)
	
	try:
		cfg.project_dir     = os.path.expanduser(CP.get('core', 'PROJECTS_PATH').strip())
		cfg.current_project = CP.get('core', 'CURRENT_PROJECT').strip()
		cfg.dict_paths      = filter(None, [os.path.expanduser(x.strip()) for x in CP.get('core', 'DICTS_PATHS').split(',')])
		cfg.jtr_path        = os.path.expanduser(CP.get('core', 'JTR_PATH').strip())
		cfg.jtr_tmout       = int(CP.get('core', 'JTR_TMOUT').strip()) # minutes

	except ConfigParser.NoOptionError:
		print "[!] Error: some fields are missing from the configuration file."
		sys.exit(1)

	# Internal settings
	cfg.db_filename = '%s.db' % cfg.prog_name
	cfg.database    = None
	cfg.cursor      = None
	cfg.domain_list = []
	cfg.domain_scope = cfg.domain_list

	if not cfg.start:

		if cfg.current_project == '':
			print "[!] No project started. Start or resume a project with '%s start <project_name>'." % (sys.argv[0])
			sys.exit(1)
		
		load_config()

	if cfg.setdomain:
		set_domain(cfg.setdomain)

	if cfg.crack == []:
		cfg.crack = [1, 2]

	if cfg.start:
		start_project(cfg.start)

	elif cfg.screenshot:
		screenshot()

	elif cfg.update_hashes:
		update_hashes(cfg.update_hashes)

	elif cfg.update_accounts:
		update_accounts(cfg.update_accounts)

	elif cfg.group:
		group_members(cfg.group)

	elif cfg.flush:
		flush()

	elif cfg.getpass:
		passwd_or_hash(cfg.getpass)

	elif cfg.crack:
		crack_hashes(cfg.crack)

	elif cfg.report:
		report()

	elif cfg.getpasswords:
		show_passwords()

	elif cfg.getuser:
		get_user(cfg.getuser)

	clean_exit()

def clean_exit(retcode=0):

	if cfg.cursor is not None:
		cfg.cursor.close()

	sys.exit(0)

def color(txt, code = 1, modifier = 0):
	return "\033[%d;3%dm%s\033[0m" % (modifier, code, txt)

def use_creds(name):
	pass

def report():
	chart_data = {}
	weak_passwords = ['password', 'p@ssword', 'password0', 'password1', 'password123', 'p@ssw0rd', 'p@ssw0rd1', 'abcd123', 'abcd1234', 'welcome1', 'welcome123', 'test']

	try:
		import pygal, lxml, cssselect, tinycss
		from collections import OrderedDict

		gen_charts = True

	except ImportError:
		print "[+] Note: To enable chart generation, the following python modules are necessary: pygal, lxml, cssselect, tinycss"
		gen_charts = False

	for d in cfg.domain_scope:

		dom_name, dom_fqdn = d

		nb_accounts = cfg.cursor.execute("SELECT COUNT(id) AS nb FROM domain_accounts WHERE domain=? AND LENGTH(nt_hash)>0", (dom_name,)).fetchone()
		nb_cracked  = cfg.cursor.execute("SELECT COUNT(id) AS nb FROM domain_accounts WHERE domain=? AND LENGTH(password)>0", (dom_name,)).fetchone()
		nb_da       = cfg.cursor.execute("SELECT COUNT(id) AS nb FROM domain_groups WHERE domain=? AND `group`='Domain Admins'", (dom_name,)).fetchone()
		nb_ea       = cfg.cursor.execute("SELECT COUNT(id) AS nb FROM domain_groups WHERE domain=? AND `group`='Enterprise Admins'", (dom_name,)).fetchone()
		nb_lm       = cfg.cursor.execute("SELECT COUNT(id) AS nb FROM domain_accounts WHERE domain=? AND `lm_hash` NOT IN ('aad3b435b51404eeaad3b435b51404ee','00000000000000000000000000000000','')", (dom_name,)).fetchone()
		nb_lep      = cfg.cursor.execute("SELECT COUNT(id) AS nb FROM domain_accounts WHERE domain=? AND LOWER(password)=LOWER(username)", (dom_name,)).fetchone()
		nb_weak     = cfg.cursor.execute("SELECT COUNT(id) AS nb FROM domain_accounts WHERE domain=? AND LOWER(password) IN('"+ "', '".join(weak_passwords)  +"')", (dom_name,)).fetchone()
		most_used   = cfg.cursor.execute("SELECT COUNT(id) AS nb, password FROM domain_accounts WHERE password != '' AND password NOT LIKE '%???????%' AND domain=? GROUP BY password ORDER BY nb DESC LIMIT 10", (dom_name,)).fetchall()

		print "- Report for domain %s (%s):" % (color(dom_name), dom_fqdn)
		print "    %s accounts in total." % color(nb_accounts[0])
		print "    %s accounts' passwords have been cracked in a short period of time (%.f%% of total)." % (color(nb_cracked[0]), (nb_cracked[0]*100)/nb_accounts[0] if nb_accounts[0]>0 else 1)
		print "    %s user accounts are member of the Domain Admins group." % color(nb_da[0])
		print "    %s user accounts are member of the Enterprise Admins group." % color(nb_ea[0])
		print "    %s user accounts use the deprecated LM password hashing algorithm." % color(nb_lm[0])
		print "    %s passwords are equal to their corresponding username." % color(nb_lep[0])
		print "    %s passwords are extremely weak." % color(nb_weak[0])
		print ""
		print "    Most used passwords:"
		for row in most_used:
			print "        %s accounts use the password '%s'" % (color(row[0]), color(row[1], 3))
		print ""

		# Generating charts if pygal is available
		if gen_charts:

			if nb_cracked[0]<10:
				continue

			chart_style = pygal.style.LightColorizedStyle(legend_font_size=11, value_font_size=9, background='#FFF')

			# chart - most used pwds
			chart_1 = pygal.HorizontalBar(width=500, height=250, legend_box_size=10, style=chart_style)
			chart_1.title = '%s - Most used passwords' % dom_name

			for row in [(x[0], x[1]) for x in most_used if x[0] > 1]:
				chart_1.add(row[1], row[0])
			
			chart_1.render_to_png(os.path.join(cfg.binder_dir, '%s.mostused.png' % dom_name))


			# chart - lm/nt cracked/uncracked
			res = cfg.cursor.execute("SELECT CASE WHEN `lm_hash`='aad3b435b51404eeaad3b435b51404ee' THEN 'NT' ELSE 'LM' END AS type, "
									"CASE WHEN `password`='' THEN 'Uncracked' ELSE 'Cracked' END AS is_cracked, COUNT(`password`) AS result "
									"FROM `domain_accounts` WHERE `domain`=? and LENGTH(`nt_hash`)>0 "
									"GROUP BY type, is_cracked", (dom_name,)).fetchall()

			chart_2 = pygal.Pie(width=275, height=200, legend_at_bottom=True, print_values=True, legend_at_bottom_columns=2, 
				value_formatter=lambda x: '%d (%d%%)' % (x, x*100/nb_accounts[0] if nb_accounts[0]>0 else 1),
				 inner_radius=.4, style=chart_style)

			chart_2.title = '%s - Cracked passwords' % dom_name

			for row in res:
				chart_2.add('%s - %s' % (row[0], row[1]), row[2])

			chart_2.render_to_png(os.path.join(cfg.binder_dir, '%s.cracked.png' % dom_name))

			# chart - password lenghts
			res = cfg.cursor.execute("SELECT LENGTH(`password`) AS nb_chars, COUNT(id) AS sum "
									"FROM `domain_accounts` "
									"WHERE `domain`=? AND nb_chars>0 AND LENGTH(`nt_hash`)>0 "
									"GROUP BY nb_chars ORDER BY nb_chars ASC", (dom_name,)).fetchall()

			lengths = OrderedDict({6: 0, 7: 0, 8: 0, 9: 0, 10: 0, 11: 0, 12: 0})

			for row in res:

				if   row[0] <= 6:  lengths[6]      += row[1]
				elif row[0] >= 12: lengths[12]     += row[1]
				else:              lengths[row[0]] += row[1]

			chart_3 = pygal.Bar(width=500, height=250, style=chart_style)
			chart_3.title = '%s - Password Lengths' % dom_name

			for l in lengths:
				if   l == 6:  s = '6 chars or less'
				elif l == 12: s = '12 chars or more'
				else: s = str(l) + ' chars'
				chart_3.add(s, lengths[l])

			chart_3.render_to_png(os.path.join(cfg.binder_dir, '%s.lengths.png' % dom_name))



def set_domain(domain):
	for d in cfg.domain_list:
		if d[0] == domain.upper() or d[1] == domain.upper():
			cfg.domain_scope = [(d[0], d[1])]
			return

	print "[!] No such domain in database."
	sys.exit(0)

def show_passwords():

	if cfg.domain_scope == cfg.domain_list:
		req = cfg.cursor.execute("SELECT `domain`, `username`, `password` FROM `domain_accounts` WHERE `password` != '' AND `password` NOT LIKE '%???????%'")
	else:
		req = cfg.cursor.execute("SELECT `domain`, `username`, `password` FROM `domain_accounts` WHERE `password` != '' AND `password` NOT LIKE '%???????%' AND `domain` IN (?)", [d[0] for d in cfg.domain_scope])

	cpt = 0
	for row in req.fetchall():
		dom, usr, psw = row
		if dom != '':
			usr = dom +'\\'+ usr
		try:
			print usr +':'+ psw
		except IOError:
			clean_exit(1)

		cpt += 1

	print "[+] %d passwords cracked." % cpt

def color(txt, code = 1, modifier = 0):
	return "\033[%d;3%dm%s\033[0m" % (modifier, code, txt)

def crack_hashes(levels=[1, 2]):

	cfg.pot_file  = os.path.join(cfg.binder_dir, 'john.pot')
	cfg.sess_file = os.path.join(cfg.binder_dir, 'john')
	cfg.dict_file = os.path.join(cfg.binder_dir, 'dict.bndr')
	cfg.hash_file = os.path.join(cfg.binder_dir, 'hashes.bndr')
	cfg.mkv_file  = os.path.join(cfg.binder_dir, 'mkv_stats.bndr')


	# start functions
	def recursive_file_listing(path, exts):
		ret = []
		for root, directories, filenames in os.walk(path):
			for filename in filenames:
				if os.path.splitext(filename)[1][1:] in exts:
					fn = os.path.join(root, filename)
					ret.append((fn, os.stat(fn).st_size))

		return ret

	def filter_lm_masks(masks):
		# For LM, skip the lowercase stuff and
		# keep only masks with len <= 7
		ret = [x.replace('?2', '?1').replace('?5', '?1') for x in masks if (len(x) <= 14)]
		seen = set()
		return [x for x in ret if not (x in seen or seen.add(x))]

	def pc(mode, i, tot):
		pc = i*100 / tot
		sys.stdout.write('--- %s attack: %d%%                \r' % (mode, pc))
		sys.stdout.flush()

	def apply_rules(file_size):

		def Mb(i): return i * 1024 * 1024
		def Kb(i): return i * 1024

		# Enable some rules according to dict size
		if file_size < Mb(70):
			return '--rules:Wordlist'
		
		if file_size < Mb(1.5):
			return '--rules:Extra'

		if file_size < Kb(300):
			return '--rules:Jumbo'

		if file_size < Kb(2):
			return '--rules:All'

		return ''

	def get_dict_list():
		dict_list = []
		valid_exts = ['txt', 'dic', 'lst']

		for p in cfg.dict_paths:
			dict_list += recursive_file_listing(p, valid_exts)

		return dict_list

	def generate_hash_file():
		res = cfg.cursor.execute("SELECT `username`, `rid`, `lm_hash`, `nt_hash` FROM domain_accounts WHERE `password`=''").fetchall()

		f = open(cfg.hash_file, 'wb')
		for row in res:
			f.write('%s:%s:%s:%s:::\n' % (row[0], row[1], row[2], row[3]))
		f.close()

	def update_dict_file():
		if os.path.exists(cfg.dict_file):
			words = map(str.strip, open(cfg.dict_file).readlines())
		else:
			words = []

		res = cfg.cursor.execute("SELECT DISTINCT `password` FROM domain_accounts WHERE `password`!='' AND `password` NOT LIKE '%???????%'").fetchall()

		for row in res:
			words.append(row[0])

		open(cfg.dict_file, 'wb').write('\n'.join(set(words)))

	def get_cracked_hashes(fmt='nt'):

		def find_good_case(passwd, nt_hash):
		
			def ntlm_hash(str):
				h = hashlib.new('md4', str.encode('utf-16le')).digest()
				return h.encode('hex').lower()

			nt_hash = nt_hash.lower()

			for p in itertools.product(*((c.upper(), c.lower()) for c in passwd)):
				if ntlm_hash(''.join(p)) == nt_hash:
					return p

		command = cfg.jtr_path +' --format=%s --pot=%s --show %s' % (fmt, cfg.pot_file, cfg.hash_file)
	
		try:
			ret = os.popen(command).readlines()
	
		except KeyboardInterrupt:
			print "\n[*] Exiting..."
			clean_exit(0)

		found = []

		for output in ret:
			
			if ':::' not in output:
				continue
			
			output = output.strip()
			#output = output.decode('utf-8')
			tab = output.split(':')

			# special case when there is a ':' in the password
			while len(tab) > 8:
				tab[1] += ':'+tab[2]; del tab[2]

			if len(tab[1]):
				uname, passwd, rid, lm_hash, nt_hash = tab[0], tab[1], int(tab[2]), tab[3], tab[4]

				if '???????' in passwd:
					continue
					
				if fmt == 'lm':
					passwd = find_good_case(passwd, nt_hash)

				if nt_hash not in cracked_in_session:

					sys.stdout.write("%s\033[0;33m>>> %s:%s\033[0m" % ("\n" if len(found) else '', uname, passwd))
					sys.stdout.flush()

					if (passwd, nt_hash) not in found:
						found.append((passwd, nt_hash))
	
					cracked_in_session.append(nt_hash)

		if len(found):

			print ""
			cfg.cursor.executemany('UPDATE `domain_accounts` SET `password`=? WHERE `nt_hash`=?', found)
			cfg.cursor.commit()

		return len(found)

	# end functions

	generate_hash_file()
	cracked_in_session = []

	# for local, single, dicts, and markov attacks, there
	# is no point to try to crack lm hashes, as the speed
	# gain is minimal and it will have the extra cost of
	# having to find the correct case.

	if 1 in levels:

		print "\r[+] Running local database attack..."
		update_dict_file()
		run(cfg.jtr_path +' --format=nt --pot=%s --nolog --wordlist=%s %s' % (cfg.pot_file, cfg.dict_file, cfg.hash_file))
		nb_cracked = get_cracked_hashes()

	if 2 in levels:

		print "\r[+] Running single mode attack..."
		run(cfg.jtr_path +' --format=nt --pot=%s --nolog --single %s' % (cfg.pot_file, cfg.hash_file))
		nb_cracked = get_cracked_hashes()

	if 3 in levels:

		cpt = 0
		dict_list = get_dict_list()	
		print "\r[+] Running dictionary attack with %d wordlists..." % len(dict_list)

		for d in dict_list:
			pc('dicts', cpt, len(dict_list))
			run(cfg.jtr_path +' --format=nt --session=%s.dict --pot=%s --wordlist=%s %s --nolog --dupe-suppression %s' % (cfg.sess_file, cfg.pot_file, d[0], apply_rules(d[1]), cfg.hash_file))
			nb_cracked = get_cracked_hashes()
			cpt += 1

	if 4 in levels:

		cpt = 0

		for fmt in ['lm', 'nt']:

			masks = ['?1?2?2?2?2?2?3?3','?1?2?2?2?2?2?2?3?3','?1?2?2?2?3?3?3?3','?1?2?2?2?2?3?3?3?3','?1?2?2?2?2?2?3?3?3?3','?1?2?2?2?2?2?2?2?3?3','?1?2?2?2?2?2?2?3','?1?2?2?2?2?3?3?3','?1?2?2?2?2?2?2?2?3','?1?2?2?2?2?2?2?3?3?3?3','?1?2?2?2?2?2?3?3?3','?1?2?2?2?2?2?2?2?2?3?3','?1?2?2?2?2?2?2?2?3?3?3?3','?1?2?2?2?2?2?2?2?2?3','?1?3?3?3?3?3?3?3?4','?1?2?2?2?2?2?2?3?3?3','?1?2?3?3?3?3?3?3','?1?2?2?2?2?3?3','?1?2?2?2?2?2?2?2?3?3?3','?1?2?2?2?2?2?2?2?2?2?3?3','?3?3?3?3?3?4?1?3?2','?1?2?2?2?2?2?3','?2?1?3?3?3?3?3?3','?1?4?2?2?3?3?3?3?3']
			
			if fmt == 'lm':
				masks = filter_lm_masks(masks)

			print "\r[+] Running mask attack on %s with %d masks..." % (fmt, len(masks))
		
			for m in masks:
				
				pc('masks', cpt, len(masks))
				run(cfg.jtr_path +" --format=%s --pot=%s --nolog --max-run-time=%d --mask=%s --max-len=%d -1=[A-Z] -2=[a-z] -3=[0-9] -4='!@#$._/' %s" % (fmt, cfg.pot_file, (cfg.jtr_tmout*60)/len(masks), m, len(m)/2, cfg.hash_file))
				nb_cracked = get_cracked_hashes(fmt)
				cpt += 1

	if 5 in levels:

		print "\r[+] Running markov attack..."
		update_dict_file()

		# Generate mkv stats from dict
		run("%s %s %s" % (os.path.join(os.path.dirname(cfg.jtr_path), 'calc_stat'), cfg.dict_file, cfg.mkv_file))
		run(cfg.jtr_path +" --format=nt --pot=%s --nolog --markov=200 --max-run-time=%d --max-len=13 --mkv-stats=%s %s" % (cfg.pot_file, cfg.jtr_tmout*60, cfg.mkv_file, cfg.hash_file))
		nb_cracked = get_cracked_hashes()

	if 6 in levels:

		from multiprocessing import cpu_count

		for fmt in ['lm', 'nt']:

			print "\r[+] Running brute-force attack on %s for %d minutes..." % (fmt, cfg.jtr_tmout)

			if not os.path.exists('%s.%s.bf.rec' % (cfg.sess_file, fmt)):
				run(cfg.jtr_path +" --format=%s --session=%s.%s.bf --pot=%s --nolog --incremental=%s --max-len=%d --max-run-time=%d --fork=%d %s" % 
					(fmt, cfg.sess_file, fmt, cfg.pot_file, 'lm_ascii' if fmt == 'lm' else 'ascii', 7 if fmt == 'lm' else 12, cfg.jtr_tmout*60, cpu_count(), cfg.hash_file))
			else:
				run(cfg.jtr_path +" --restore=%s.%s.bf" % (cfg.sess_file, fmt))
			
			nb_cracked = get_cracked_hashes(fmt)

	cracked = cfg.cursor.execute("SELECT COUNT(rid) AS nb FROM `domain_accounts` WHERE `password`!='' AND `password` NOT LIKE '%???????%'").fetchone()
	print "[+] %d passwords cracked." % cracked[0]

def user_list():

	users = {}
	res = cfg.cursor.execute("SELECT id, rid, domain FROM domain_accounts").fetchall()
	for row in res:
		id, rid, dom = row
		users[(rid, dom)] = id

	return users

def update_accounts(file):

	existing_users = user_list()
	users_ins = []
	users_upd = []
	groups = []
	dom_short = ''

	regex_acct = re.compile(u"index: (.+) RID: (.+) acb: (.+) Account: (.+)\tName: (.+)\tDesc: (.+)$")
	regex_grp = re.compile(u"Group '(.+)' \(RID: ([0-9]+)\) has member: ([^$]+)")

	print "[+] Reading groups..."
	for l in file.readlines():
		l = l.strip()
		l = l.decode('latin1', 'ignore').encode('utf8', 'ignore')

		if l.startswith('Domain Name: '):
			domain = l.split(' ', 3)
			dom_short, dom_long = handle_domains(domain[2])

		if 'Account:' in l and 'Name:' in l:
			res = regex_acct.search(l)

			try:
				_, rid, _, usr, name, desc = res.groups()

				if usr.startswith(('IUSR_', 'IWAM_', 'SUPPORT_')):
					continue

				rid = int(rid, 16)

				if not len(dom_short):
					dom_short, dom_long = handle_domains(dom_short)

				if (rid, dom_short) in existing_users:
					users_upd.append((name, desc, existing_users[(rid, dom_short)]))
				else:
					users_ins.append((rid, dom_short, usr, name, '', '', '', desc))
			except:
				pass

		if 'has member:' in l:
			res = regex_grp.search(l)

			try:
				grp, rid, usr = res.groups()
				grp = grp.replace("'\\''", "'")
				rid = int(rid)
				dom, usr = usr.split('\\')
				groups.append((rid, dom.upper(), grp, usr))
			except:
				pass

	print "[+] Updating database..."

	if len(users_upd):
		res_u = cfg.cursor.executemany('UPDATE domain_accounts SET name=?, descr=? WHERE id=?', users_upd)
		print "[+] %d user accounts updated." % res_u.rowcount

	if len(users_ins):
		res_i = cfg.cursor.executemany('INSERT INTO domain_accounts (rid, domain, username, name, password, lm_hash, nt_hash, descr, active) VALUES(?, ?, ?, ?, ?, ?, ?, ?, 0)', users_ins)
		print "[+] %d user accounts inserted." % res_i.rowcount

	if len(groups):
		res_g = cfg.cursor.executemany('INSERT INTO domain_groups (rid, domain, `group`, username) VALUES(?, ?, ?, ?)', groups)
		print "[+] %d group memberships updated." % res_g.rowcount

	cfg.cursor.commit()
	print "[+] Done."

def handle_domains(dom_str=''):

	dom_str = dom_str.upper()

	if dom_str == '':
		dom_short = raw_input("Short name for the new domain? ").upper()
		dom_long = raw_input("Domain FQDN for '%s'? " % dom_short).upper()
		cfg.cursor.execute("INSERT INTO domains(domain, fqdn) VALUES(?, ?)", (dom_short, dom_long))


	elif '.' in dom_str:

		dom_long = dom_str
		for d in cfg.domain_list:
			if d[1] == dom_str:
				return d

		dom_short = raw_input("Short name for '%s'? " % dom_str).upper()
		cfg.cursor.execute("INSERT INTO domains(domain, fqdn) VALUES(?, ?)", (dom_short, dom_long))

	else:

		dom_short = dom_str
		for d in cfg.domain_list:
			if d[0] == dom_str:
				return d

		dom_long = raw_input("Domain FQDN for '%s'? " % dom_str).upper()
		cfg.cursor.execute("INSERT INTO domains(domain, fqdn) VALUES(?, ?)", (dom_short, dom_long))

	cfg.cursor.commit()	
	cfg.domain_list.append((dom_short, dom_long))
	
	return dom_short, dom_long

def update_hashes(file):

	res = -1
	while res not in range(0, len(cfg.domain_list) + 1):

		for k in range(len(cfg.domain_list)):
			print "[%d] %s" % (k, cfg.domain_list[k][0])
		print "[%d] New domain" % len(cfg.domain_list)
		print ""

		try:
			res = int(raw_input('Which domain is this for? ').strip())

		except KeyboardInterrupt:
			clean_exit(0)

		except:
			continue

	if res == len(cfg.domain_list):
		curr_dom, dom_long = handle_domains()
	else:
		curr_dom, dom_long = cfg.domain_list[res]

	existing_users = user_list()

	print "[+] Reading cracked passwords..."

	cfg.pot_file  = os.path.join(cfg.binder_dir, 'john.pot')

	cleartexts = {}
	cracked  = run(cfg.jtr_path + ' --format=LM --pot=%s --show %s' % (cfg.pot_file, file.name))
	cracked += run(cfg.jtr_path + ' --format=NT --pot=%s --show %s' % (cfg.pot_file, file.name))

	for l in cracked.split('\n'):

		if ':::' not in l: continue
		
		l = l.strip()
		l = l.decode('latin1', 'ignore').encode('utf8', 'ignore')
		tab = l.split(':')

		# special case when there is a ':' in the password
		while len(tab) > 8:
			tab[1] += ':'+tab[2]; del tab[2]

		if len(tab[1]) > 0 and '???????' not in tab[1]:
			cleartexts[tab[4]] = tab[1]

	users_ins = []
	users_upd = []

	for l in file.readlines():

		if ':::' not in l or '$' in l: continue
		
		l = l.strip()
		l = l.decode('latin1', 'ignore').encode('utf8', 'ignore')
		tab = l.split(':')
		tab[0] = tab[0].replace('(current)', '')
		tab[0] = tab[0].replace('(current-disabled)', '')

		# Skip password history, service accounts and machine accounts
		if '(hist_' in tab[0] or tab[0].startswith(('IUSR_', 'IWAM_', 'SUPPORT_')) or tab[0].endswith('$'):
			continue

		tab[1] = re.sub("[^0-9]", "", tab[1])
		rid, uname, lm_hash, nt_hash = int(tab[1]) if len(tab[1]) else 0, tab[0], tab[2], tab[3]

		if lm_hash.lower() in ['no password*********************', '00000000000000000000000000000000']:
			lm_hash = 'aad3b435b51404eeaad3b435b51404ee'

		password = cleartexts[nt_hash] if nt_hash in cleartexts else ''

		if '\\' in uname:
			dom_extract, uname = uname.split('\\')
			dom_short, dom_long = handle_domains(dom_extract)
	
		else:
			dom_short = curr_dom

		if (rid, dom_short) in existing_users:
			users_upd.append((uname, password, lm_hash, nt_hash, 0, existing_users[(rid, dom_short)]))
			if uname =='SOUDX003':
				print (uname, password, lm_hash, nt_hash, 0, existing_users[(rid, dom_short)])
		else:
			users_ins.append((rid, dom_short, uname, password, lm_hash, nt_hash, 0))

	print "[+] Updating database..."

	if len(users_upd):
		res_u = cfg.cursor.executemany('UPDATE domain_accounts SET username=?, password=?, lm_hash=?, nt_hash=?, active=? WHERE id=?', users_upd)
		print "[+] %d user accounts updated." % res_u.rowcount
	
	if len(users_ins):
		res_i = cfg.cursor.executemany('INSERT INTO domain_accounts (rid, domain, username, password, lm_hash, nt_hash, active) VALUES(?, ?, ?, ?, ?, ?, ?)', users_ins)
		print "[+] %d user accounts inserted." % res_i.rowcount
	
	if len(cleartexts):
		print "[+] %d unique cleartexts." % len(cleartexts)

	cfg.cursor.commit()
	print "[+] Done."

def flush():
	print "[+] Flushing user accounts from database..."
	cfg.cursor.execute('DELETE FROM `domain_groups`')
	cfg.cursor.execute('DELETE FROM `domain_accounts`')
	cfg.cursor.execute('DELETE FROM `domains`')
	cfg.cursor.commit()
	print "[+] Done."

def group_members(grpname, dom=None, lvl=0):

	def fmt(row):
		gname = color(row[1]+'\\'+row[0], 2, 1)
		uname = color(row[1] +'\\'+ row[2].ljust(22), 3, 1)
		u_rid = str(row[3]).ljust(6) if row[3] is not None else None
		desc  = color(str(row[5] if row[5] is not None else ''), 4)
		name  = color(str(row[4] if row[4] is not None else '').ljust(20), 4)
		pswd  = color(str(row[6] if row[6] is not None else '').ljust(13), 6, 1)

		return gname, uname, u_rid, desc, name, pswd, row[1], row[2]

	if dom == None:
		res = cfg.cursor.execute("SELECT a.`group`, a.`domain`, a.`username` AS usr_or_grp, b.`rid` as ridb, b.`name`, b.`descr`, b.`password` "
			"FROM domain_groups a "
			"LEFT JOIN domain_accounts b ON (lower(a.`domain`||'\'||a.`username`)=lower(b.`domain`||'\'||b.`username`)) "
			"WHERE UPPER(a.`group`) LIKE UPPER(?) "
			"AND a.`domain` IN('"+ "','".join([d[0] for d in cfg.domain_scope]) +"') "
			"GROUP BY usr_or_grp "
			"ORDER BY a.`domain`||'\'||a.`username`", (grpname,)).fetchall()
	
		if len(res) == 0:
			print "[!] Error: No such group."
			clean_exit(1)
	
	else:
			res = cfg.cursor.execute("SELECT a.`group`, a.`domain`, a.`username` AS usr_or_grp, b.`rid` as ridb, b.`name`, b.`descr`, b.`password` "
			"FROM domain_groups a "
			"LEFT JOIN domain_accounts b ON (lower(a.`domain`||'\'||a.`username`)=lower(b.`domain`||'\'||b.`username`)) "
			"WHERE UPPER(a.`group`) LIKE UPPER(?) AND a.`domain`=?"
			"ORDER BY a.`domain`||'\'||a.`username`", (grpname,dom)).fetchall()	

	hdr = ' '*lvl*5 + ('\\_ ' if lvl > 0 else '')

	direct_users = []

	if len(res) == 0:
		print hdr+"No members found."

	for row in res:
		gname, uname, u_rid, desc, name, pswd, dom, usr_or_grp = fmt(row)

		if u_rid == None: # This is a sub-group, not a username

			print hdr+"Group '{}' contains sub-group {}".format(gname, uname)
			group_members(usr_or_grp, dom, 1)
		
		else:
			if lvl == 0:
				direct_users.append(row)
			else:
				print hdr+ "Grp: {} Usr: {} RID: {} Pwd: {} Name: {} Desc: {}".format(gname, uname, u_rid, pswd, name, desc)

	print ""
	for usr in direct_users:
		gname, uname, u_rid, desc, name, pswd, dom, usr_or_grp = fmt(usr)

		print "[+] Group {} has top-level member: {} RID: {}   Pwd: {} Name: {} Desc: {}".format(gname, uname, u_rid, pswd, name, desc)

def get_user(username):
	
	if '\\' in username: # we specified the domain in the username instead of with -d
		dom, usr = username.split('\\')
		usr = '%'+ usr.upper() + '%'
		res = cfg.cursor.execute("SELECT * FROM domain_accounts WHERE UPPER(`domain`)=UPPER(?) AND (UPPER(`username`) LIKE ? OR UPPER(`name`) LIKE ?)", (dom, usr, usr,))
	else:
		usr = '%'+ username.upper() + '%'
		if cfg.domain_scope == cfg.domain_list: # Include all domains
			res = cfg.cursor.execute("SELECT * FROM domain_accounts WHERE (UPPER(`username`) LIKE ? OR UPPER(`name`) LIKE ?)", (usr,usr,))
		else: # Filter on domain(s) specified
			res = cfg.cursor.execute("SELECT * FROM domain_accounts WHERE (UPPER(`username`) LIKE ? OR UPPER(`name`) LIKE ?) AND `domain` IN('"+ "','".join([d[0] for d in cfg.domain_scope]) +"')", (usr,usr,))

	res = res.fetchall()

	for row in res:
		print color("Username : %s" % row[3], 9, 1)
		print "RID      : %d" % row[0]
		print "Domain   : %s" % row[2]
		print "Password : %s" % row[4]
		print "LM Hash  : %s" % row[5]
		print "NT Hash  : %s" % row[6]
		print "Real Name: %s" % row[7]
		print "Descript : %s" % row[8]
	
	 	grps = cfg.cursor.execute("SELECT `rid`, `group` FROM domain_groups WHERE LOWER(`username`)=LOWER(?) AND LOWER(`domain`)=LOWER(?) ORDER BY rid ASC", (row[3],row[2])).fetchall()
		print "\nGroup Memberships:\n   - %s" % '\n   - '.join(["%s (%d)" % (x[1], x[0]) for x in set(grps)])
		print ""

def screenshot():

	filename = datetime.datetime.now().strftime("%Y-%m-%d_%H.%M.%S") + '.png'

	if os.path.exists(cfg.shots_dir):
		full_path = os.path.join(cfg.shots_dir, filename)
	else:
		full_path = os.path.join('/tmp', '.binder.png')

	os.popen('scrot -s "%s"' % full_path)
	os.popen('xclip -selection clipboard -t image/png "%s"' % full_path)

def load_config():

	if not os.path.exists(cfg.config_file):
		print "[!] No project started. Start or resume a project with '%s start|resume <project_name>'." % sys.argv[0]
		clean_exit(1)

	cfg.base_dir        = os.path.join(cfg.project_dir, cfg.current_project)
	cfg.binder_dir      = os.path.join(cfg.base_dir, '.'+cfg.prog_name)
	cfg.database        = os.path.join(cfg.binder_dir, cfg.db_filename)
	cfg.shots_dir       = os.path.join(cfg.base_dir, 'screenshots')
	cfg.axfr_dir        = os.path.join(cfg.base_dir, 'axfr')
	cfg.enum_dir        = os.path.join(cfg.base_dir, 'enum')
	cfg.scans_dir       = os.path.join(cfg.base_dir, 'scans')

	if not os.path.exists(cfg.database):
		print "[!] Database file not found for this project."
		clean_exit(1)

	cfg.cursor = sqlite3.connect(cfg.database)
	cfg.cursor.text_factory = str

	res = cfg.cursor.execute("SELECT `domain`, `fqdn` FROM domains").fetchall()
	for row in res:
		cfg.domain_list.append((row[0], row[1]))

def start_project(name):

	project_dir = os.path.join(cfg.project_dir, name)

	if os.path.exists(project_dir):
		print "[+] Resuming project %s..." % name

	else:
		print "[+] Starting project %s..." % name
		os.mkdir(project_dir)
	
		try:
			print "[+] Creating configuration files..."
			os.mkdir(os.path.join(project_dir, '.'+cfg.prog_name))
			os.mkdir(os.path.join(project_dir, 'screenshots'))
			os.mkdir(os.path.join(project_dir, 'axfr'))
			os.mkdir(os.path.join(project_dir, 'enum'))
			os.mkdir(os.path.join(project_dir, 'scans'))
		except:
			pass

	# Update config file
	import fileinput

	for line in fileinput.input(cfg.config_file, inplace=True):
		if line.startswith('CURRENT_PROJECT ='):
			print 'CURRENT_PROJECT = %s' % name
		else:
			print line,

	if not os.path.exists(os.path.join(project_dir, '.'+cfg.prog_name)):
		os.mkdir(os.path.join(project_dir, '.'+cfg.prog_name))

	cfg.database = os.path.join(project_dir, '.'+cfg.prog_name, cfg.db_filename)

	if not os.path.exists(cfg.database):

		print "[+] Creating database..."
		cfg.cursor = sqlite3.connect(cfg.database)
		cfg.cursor.execute('CREATE TABLE domain_accounts (id INTEGER PRIMARY KEY, rid, domain varchar(32), username varchar(32), password varchar(32), lm_hash varchar(32), nt_hash varchar(32), name varchar(32), descr varchar(32), active INTEGER)')
		cfg.cursor.execute('CREATE TABLE domain_controllers (id INTEGER PRIMARY KEY, domain varchar(32), hostname varchar(32), ipaddr varchar(32), allow_axfr INTEGER, allow_anon_enum INTEGER)')
		cfg.cursor.execute('CREATE TABLE domain_groups (id INTEGER PRIMARY KEY, rid INTEGER, domain varchar(32), `group` varchar(32), username varchar(32))')
		cfg.cursor.execute('CREATE TABLE domains (id INTEGER PRIMARY KEY, domain varchar(32), fqdn varchar(64))')
		cfg.cursor.commit()
		cfg.cursor.close()

	print "[+] Done."

def passwd_or_hash(uname):

	if '\\' in uname:
		dom, usr = uname.split('\\')

		res = cfg.cursor.execute("SELECT rid, domain, username, password, nt_hash "
			"FROM domain_accounts "
			"WHERE LOWER(domain)=LOWER(?) "
			"AND LOWER(username)=LOWER(?) "
			"LIMIT 1", (dom, usr,))

	else:
		res = cfg.cursor.execute("SELECT rid, domain, username, password, nt_hash "
			"FROM domain_accounts "
			"WHERE LOWER(username)=LOWER(?) "
			"LIMIT 1", (uname,))

	fetch = res.fetchall()

	if len(fetch) == 0:
		print "[!] Error: user not found in database."
		clean_exit(1)
	
	rid, domain, username, password, nt_hash = fetch[0]
	print password if password != "" else nt_hash

def run(cmd):
	if cfg.verbose:
		print ""
		print color("[>] %s" % cmd, 2, 1)

	try:
		process = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.STDOUT, env=os.environ.copy())
		ret = process.stdout.read()
		if cfg.verbose:
			print color("[<] %s" % ret.strip(), 2) 
		return ret.strip() + "\n"

	except KeyboardInterrupt:
		from signal import SIGINT
		print ""
		os.kill(process.pid, SIGINT)
		clean_exit(1)

if __name__ == "__main__":

	if len(sys.argv) == 1:
		sys.argv.append('--help')

	main()

#!/usr/bin/env python
import sys
import os
import subprocess
import socket
import shlex
import re
import hashlib
import binascii
import argparse
import ConfigParser
import ldif_import

from threading import Thread
from time import sleep
from datetime import datetime
from itertools import product
from operator import itemgetter
from multiprocessing import cpu_count
from random import choice
from signal import SIGINT

try:
	import sqlite3
except:
	print "[!] Please install python-sqlite3 extension."
	sys.exit(0)

__version__ = 2.0
__prog_name__ = 'binder'

def main():

	parser = argparse.ArgumentParser(description='%s version %.1f' % (__prog_name__, __version__))
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
		'-x', '--update-hashes',
		action='store',
		dest='update_hashes',
		metavar='<filename>',
		type=argparse.FileType('r'),
		help='Load creds into db from dump file. Provide pwdump-style file',
		default=False)

	exclusive.add_argument(
		'-l', '--ldif-import',
		action='store',
		dest='ldif_file',
		metavar='<filename>',
		type=argparse.FileType('r'),
		help='Load user and group information from LDIF export. Provide LDIF file. The LDIF file can be obtained with: "ldapsearch -h <ip> -x -D <username> -w <password> -b <base DN> -E pr=1000/noprompt -o ldif-wrap=no > ldap.output"',
		default=False)

	exclusive.add_argument(
		'-a', '--update-accounts',
		action='store',
		dest='update_accounts',
		metavar='<filename>',
		type=argparse.FileType('r'),
		help='Load user and group info into db. Provide enum4linux output file',
		default=False)

	exclusive.add_argument('-c', '--crack',
		action='store',
		dest='crack',
		metavar='<levels>',
		type=int,
		nargs='*',
		help='Run multiple password cracking attacks. Pass a space-separated list of levels. Levels: 1: Local db, 2: single, 3: dictionaries/rules, 4: markov, 5: masks, 6: brute-force. Default: 1 2',
		default=False)

	exclusive.add_argument(
		'-g', '--group',
		action='store',
		metavar='<group_name>',
		help='Return group members with usernames and passwords (if cracked)',
		default=False)

	exclusive.add_argument('-f', '--flush',
		action='store_true',
		help='Delete user and group data from db',
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

	exclusive.add_argument('-S', '--search',
		action='store',
		dest='search',
		metavar='<search_term>',
		help='Search the database.',
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

		if os.path.exists(sample):
			default_conf = open(sample).read()
			open(cfg.config_file, 'w').write(default_conf)

			print "[*] Sample configuration file copied to %s" % cfg.config_file
			print "[*] Please edit the file and run this program again."

		else:
			print "[*] Please copy the config.sample file to ~/.binder, edit it, and run this program again."

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
	cfg.domain_list = {}
	cfg.job_running = False

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

	elif cfg.ldif_file:
		import_ldif(cfg.ldif_file)

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

	elif cfg.search:
		search_db(cfg.search)

	clean_exit()

def clean_exit(retcode=0):

	if cfg.cursor is not None:
		cfg.cursor.close()

	cfg.job_running = False

	sys.exit(0)

def color(txt, code = 1, modifier = 0):
	return "\033[%d;3%dm%s\033[0m" % (modifier, code, txt)

def domain_id_from_name(name):
	for k, v in cfg.domain_list.iteritems():
		if v[0].upper() == name:
			return k
	return False

def get_users(dom_id):
	users = {}

	res = cfg.cursor.execute("""
		SELECT rid, domain_id, username, password, lm_hash, nt_hash, name, descr 
		FROM domain_accounts 
		WHERE domain_id = ?""", (dom_id,)).fetchall()

	for row in res:
		users[row[0]] = row

	return users

def report():
	chart_data = {}
	weak_passwords = ['password', 'p@ssword', 'password0', 'password1', 'password123', 'p@ssw0rd', 'p@ssw0rd1', 'abcd123', 'abcd1234', 'welcome1', 'welcome123', 'test']

	try:
		import pygal, lxml, cssselect, tinycss
		from collections import OrderedDict

		gen_charts = True

	except ImportError:
		print "[+] Note: To enable chart generation, the following python modules are necessary: pygal, lxml, cssselect, tinycss, cairosvg"
		gen_charts = False

	for dom_id in cfg.domain_scope:

		dom_name, dom_fqdn = cfg.domain_list[dom_id]

		nb_accounts = cfg.cursor.execute("SELECT COUNT(rid) AS nb FROM domain_accounts WHERE domain_id = ?", (dom_id,)).fetchone()
		nb_cracked  = cfg.cursor.execute("SELECT COUNT(rid) AS nb FROM domain_accounts WHERE domain_id = ? AND LENGTH(password)>0", (dom_id,)).fetchone()
		nb_da       = cfg.cursor.execute("SELECT COUNT(idx) AS nb FROM group_members WHERE domain_id = ? AND `group_id` = 512", (dom_id,)).fetchone()
		nb_ea       = cfg.cursor.execute("SELECT COUNT(idx) AS nb FROM group_members WHERE domain_id = ? AND `group_id` = 519", (dom_id,)).fetchone()
		nb_lm       = cfg.cursor.execute("SELECT COUNT(rid) AS nb FROM domain_accounts WHERE domain_id = ? AND `lm_hash` NOT IN ('aad3b435b51404eeaad3b435b51404ee','00000000000000000000000000000000','')", (dom_id,)).fetchone()
		nb_lep      = cfg.cursor.execute("SELECT COUNT(rid) AS nb FROM domain_accounts WHERE domain_id = ? AND LOWER(password)=LOWER(username)", (dom_id,)).fetchone()
		nb_weak     = cfg.cursor.execute("SELECT COUNT(rid) AS nb FROM domain_accounts WHERE domain_id = ? AND LOWER(password) IN('"+ "', '".join(weak_passwords)  +"')", (dom_id,)).fetchone()
		most_used   = cfg.cursor.execute("SELECT COUNT(rid) AS nb, password FROM domain_accounts WHERE password != '' AND password NOT LIKE '%???????%' AND domain_id = ? GROUP BY password ORDER BY nb DESC LIMIT 10", (dom_id,)).fetchall()

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
									"FROM `domain_accounts` WHERE `domain_id`=? and LENGTH(`nt_hash`)>0 "
									"GROUP BY type, is_cracked", (dom_id,)).fetchall()

			chart_2 = pygal.Pie(width=275, height=200, legend_at_bottom=True, print_values=True, legend_at_bottom_columns=2, 
				value_formatter=lambda x: '%d (%d%%)' % (x, x*100/nb_accounts[0] if nb_accounts[0]>0 else 1),
				 inner_radius=.4, style=chart_style)

			chart_2.title = '%s - Cracked passwords' % dom_name

			for row in res:
				chart_2.add('%s - %s' % (row[0], row[1]), row[2])

			chart_2.render_to_png(os.path.join(cfg.binder_dir, '%s.cracked.png' % dom_name))

			# chart - password lenghts
			res = cfg.cursor.execute("SELECT LENGTH(`password`) AS nb_chars, COUNT(rid) AS sum "
									"FROM `domain_accounts` "
									"WHERE `domain_id`=? AND nb_chars>0 AND LENGTH(`nt_hash`)>0 "
									"GROUP BY nb_chars ORDER BY nb_chars ASC", (dom_id,)).fetchall()

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
	cfg.domain_scope = []

	for dom_id, d in cfg.domain_list.iteritems():
		if d[0] == domain.upper() or d[1] == domain.upper():
			cfg.domain_scope.append(dom_id)
			return

	print "[!] No such domain in database."
	sys.exit(0)

def show_passwords():

	req = cfg.cursor.execute("SELECT `domain_id`, `username`, `password` FROM `domain_accounts` WHERE `password` != '' AND `password` NOT LIKE '%%???????%%' AND `domain_id` IN (%s)" %  ','.join(map(str, cfg.domain_scope)))

	cpt = 0
	for row in req.fetchall():
		dom_id, usr, psw = row
		usr = '%s\\%s' % (cfg.domain_list[dom_id][0], usr)
		print usr +':'+ psw
		cpt += 1

	print "[+] %d passwords cracked." % cpt

def search_db(keyword):

	def formatted_table(headers, data):
		columns = []
		vsep = '|'
		separator = '+'

		columns = tuple(map(lambda x: x[0], headers))
		tablesize = [map(len, [str(_) for _ in row]) for row in [columns]+data]

		for w in map(max, zip(*tablesize)):
			vsep += " %-"+"%ss |" % (w,)
			separator += '-'*w + '--+'

		ret = separator + '\n' + vsep % columns + '\n' + separator + '\n'
		ret += '\n'.join(vsep % row for row in data) 
		ret += '\n' + separator
		return ret

	scope = ','.join(map(str, cfg.domain_scope))

	keyword = '%'+keyword+'%'
	res_users = cfg.cursor.execute("""
		SELECT d.domain, a.username, IFNULL(a.password, '') AS password,
		CAST(a.rid AS text) AS rid, a.name AS fullname, a.descr AS description
		FROM domain_accounts a
		LEFT JOIN domains d ON (d.id = a.domain_id)
		WHERE a.name LIKE ? OR a.username LIKE ? OR a.descr LIKE ?
		AND a.domain_id IN (%s)
		ORDER BY a.username
	""" % scope, (keyword, keyword, keyword))

	res_groups = cfg.cursor.execute("""
		SELECT d.domain, g.name AS `group`, CAST(g.rid AS text) AS rid
		FROM domain_groups g
		LEFT JOIN domains d ON (d.id = g.domain_id)
		WHERE g.name LIKE ? AND g.domain_id IN (%s)
		ORDER BY g.name
	""" % scope, (keyword,))

	headers_users = res_users.description
	headers_groups = res_groups.description

	data_users = [tuple([_[:70] + '...' if _ and len(_) > 70 else _ for _ in d]) for d in res_users.fetchall()]
	data_groups = [tuple([_[:70] + '...' if _ and len(_) > 70 else _ for _ in d]) for d in res_groups.fetchall()]

	if len(data_users) > 0:
		print formatted_table(headers_users, data_users)

	if len(data_groups) > 0:
		print formatted_table(headers_groups, data_groups)

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
		'''Modify a list of masks for use with the LM format'''

		ret = []
		for m in [x.replace('?2', '?1').replace('?5', '?1') for x in masks]:
			if len(m) > 14:
				ret.append(m[:14])
				ret.append(m[14:])
			else:
				ret.append(m)

		seen = set()
		return [x for x in ret if not (x in seen or seen.add(x))]

	def get_masks_from_dict():

		lines = open(cfg.dict_file).readlines()

		charsets = {
			1: 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
			2: 'abcdefghijklmnopqrstuvwxyz',
			3: '0123456789',
			4: '!@#$./_',
			5: '',
		}

		masks = {}

		for word in lines:
			word = word.strip()

			m = ''
			for c in word:
				if c in charsets[1]:
					m += '?1'
				elif c in charsets[2]:
					m += '?2'
				elif c in charsets[3]:
					m += '?3'
				elif c in charsets[4]:
					m += '?4'
				else:
					if c not in charsets[5]:
						charsets[5] += c
					m += '?5'

			if m not in masks:
				masks[m] = 1
			else:
				masks[m] += 1

		sorted_masks = sorted(masks.items(), key=itemgetter(1), reverse=True)

		# Take only the top 10 masks
		return [m[0] for m in sorted_masks[:10]]

	def pc(mode, i, tot):
		pc = i*100 / tot
		sys.stdout.write('--- %s attack: %d%%\r' % (mode, pc))
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
		res = cfg.cursor.execute("SELECT `username`, `rid`, `lm_hash`, `nt_hash` FROM domain_accounts WHERE `password` IS NULL").fetchall()

		with open(cfg.hash_file, 'w') as f:
			for row in res:
				f.write('%s:%s:%s:%s:::\n' % (row[0], row[1], row[2], row[3]))

	def update_dict_file():
		if os.path.exists(cfg.dict_file):
			words = map(str.strip, open(cfg.dict_file).readlines())
		else:
			words = []

		res = cfg.cursor.execute("SELECT DISTINCT `password` FROM domain_accounts WHERE `password` IS NOT NULL AND `password` NOT LIKE '%???????%'").fetchall()

		for row in res:
			words.append(row[0])

		open(cfg.dict_file, 'wb').write('\n'.join(set(words)))

	def monitor_crack_job(fmt='nt', mode='bf', delay=2):
		sleep(.3)

		cpt = 0
		while cfg.job_running:
			try:
				pc('%s %s' % (mode, fmt), cpt, cfg.jtr_tmout*60)
				sleep(delay)
				cpt += delay
				get_cracked_hashes(fmt)
			except:
				print "\nExiting..."
				clean_exit(1)

	def get_cracked_hashes(fmt='nt'):

		def find_good_case(passwd, nt_hash):

			nt_hash = nt_hash.lower()

			for p in product(*((c.upper(), c.lower()) for c in passwd)):

				p = ''.join(p)
				h = hashlib.new('md4', p.encode('utf-16le')).digest()

				if nt_hash == h.encode('hex').lower():
					return p

			return False

		command = cfg.jtr_path +' --format=%s --pot=%s --show %s' % (fmt, cfg.pot_file, cfg.hash_file)

		found = []
		for output in os.popen(command).readlines():

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

					sys.stdout.write(' '*70+"\r%s\033[0;33m>>> %s:%s\033[0m" % ("\n" if len(found) else '', uname, passwd))
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

		print "\r[+] Running markov attack..."
		update_dict_file()

		# Generate mkv stats from dict
		run("%s %s %s" % (os.path.join(os.path.dirname(cfg.jtr_path), 'calc_stat'), cfg.dict_file, cfg.mkv_file))
		run(cfg.jtr_path +" --format=nt --pot=%s --nolog --markov=200 --max-run-time=%d --max-len=13 --mkv-stats=%s %s" % (cfg.pot_file, cfg.jtr_tmout*60, cfg.mkv_file, cfg.hash_file))
		nb_cracked = get_cracked_hashes()

	if 5 in levels:

		update_dict_file()
		masks_from_dict = get_masks_from_dict()

		for fmt in ['lm', 'nt']:
			# masks = ['?1?2?2?2?2?2?3?3','?1?2?2?2?2?2?2?3?3','?1?2?2?2?3?3?3?3','?1?2?2?2?2?3?3?3?3','?1?2?2?2?2?2?3?3?3?3','?1?2?2?2?2?2?2?2?3?3','?1?2?2?2?2?2?2?3','?1?2?2?2?2?3?3?3','?1?2?2?2?2?2?2?2?3','?1?2?2?2?2?2?2?3?3?3?3','?1?2?2?2?2?2?3?3?3','?1?2?2?2?2?2?2?2?2?3?3','?1?2?2?2?2?2?2?2?3?3?3?3','?1?2?2?2?2?2?2?2?2?3','?1?3?3?3?3?3?3?3?4','?1?2?2?2?2?2?2?3?3?3','?1?2?3?3?3?3?3?3','?1?2?2?2?2?3?3','?1?2?2?2?2?2?2?2?3?3?3','?1?2?2?2?2?2?2?2?2?2?3?3','?3?3?3?3?3?4?1?3?2','?1?2?2?2?2?2?3','?2?1?3?3?3?3?3?3','?1?4?2?2?3?3?3?3?3']

			masks = filter_lm_masks(masks_from_dict) if fmt == 'lm' else masks_from_dict
			print "\r[+] Running mask attack on %s with %d masks..." % (fmt, len(masks))

			for m in masks:

				cmd = cfg.jtr_path +" --format=%s --pot=%s --nolog --max-run-time=%d --mask=%s --max-len=%d --fork=%d -1=[A-Z] -2=[a-z] -3=[0-9] -4='!@#$._/' %s" % (fmt, cfg.pot_file, cfg.jtr_tmout*60, m, len(m)/2, cpu_count(), cfg.hash_file)
				thread = Thread(target=run, args=(cmd,))
				thread.start()

				monitor_crack_job(fmt, 'mask %s' % m, 10)

	if 6 in levels:

		for fmt in ['lm', 'nt']:

			print "\r[+] Running brute-force attack on %s for %d minutes..." % (fmt, cfg.jtr_tmout)
			if not os.path.exists('%s.%s.bf.rec' % (cfg.sess_file, fmt)):

				charset = 'lm_ascii' if fmt == 'lm' else 'ascii'
				max_length = 7 if fmt == 'lm' else 12
				cmd = cfg.jtr_path +" --format=%s --session=%s.%s.bf --pot=%s --nolog --incremental=%s --max-len=%d --max-run-time=%d --fork=%d %s" % (fmt, cfg.sess_file, fmt, cfg.pot_file, charset, max_length, cfg.jtr_tmout*60, cpu_count(), cfg.hash_file)

			else:

				cmd = cfg.jtr_path +" --restore=%s.%s.bf" % (cfg.sess_file, fmt)

			thread = Thread(target=run, args=(cmd,))
			thread.start()

			monitor_crack_job(fmt, 'bf', 10)

	cracked = cfg.cursor.execute("SELECT COUNT(rid) AS nb FROM `domain_accounts` WHERE `password` IS NOT NULL AND `password` NOT LIKE '%???????%'").fetchone()
	print "[+] %d passwords cracked." % cracked[0]

def import_ldif(ldif_file):

	if not ldif_import.get_confirmation('Do you really want to update the database for the "%s" project?' % cfg.current_project):
		clean_exit()

	ldif_import.cfg = cfg
	ldif_import.main()

def sanitize(s):
	s = s.strip()
	s = s.decode('latin1', 'ignore')
	s = s.encode('utf8', 'ignore')
	return s

def parse_enum(file):

	users = {}
	groups = {}
	members = []

	user_to_rid = {}
	group_to_rid = {}

	regex_accounts = re.compile(u"index: (.+) RID: (.+) acb: (.+) Account: (.+)\tName: (.+)\tDesc:(.+)?$")
	regex_members = re.compile(u"Group '(.+)' \(RID: ([0-9]+)\) has member: (.+)$")
	regex_groups = re.compile(u"group:\[(.+)\] rid:\[(.+)\]$")

	lines = file.readlines()
	lines = map(sanitize, lines)
	dom_id = None

	for l in lines:

		if l.startswith('Domain Name: ') or l.startswith('[+] Got domain/workgroup name:'):
			domain = l.split(' ')
			dom_short, dom_long, dom_id = handle_domains(domain[-1])

	users = get_users(dom_id)

	for l in lines:

		if 'Account:' in l and 'Name:' in l:
			res = regex_accounts.search(l)
			_, rid, _, usr, name, desc = res.groups()
			desc = '' if desc is None else desc

			if usr.startswith(('IUSR_', 'IWAM_', 'SUPPORT_')):
				continue

			rid = int(rid, 16)

			if not len(dom_short):
				dom_short, dom_long, dom_id = handle_domains(dom_short)

			if rid in users:
				users[rid] = (rid, dom_id, usr, users[rid][3], users[rid][4], users[rid][5], name, desc)
			else:
				users[rid] = (rid, dom_id, usr, None, None, None, name, desc)

	user_to_rid = {b[2]: a for a, b in users.iteritems()}

	for l in lines:

		if l.startswith('group:'):
			res = regex_groups.search(l)
			grp, rid = res.groups()
			rid = int(rid, 16)
			groups[rid] = (rid, dom_id, grp)
			group_to_rid[grp] = rid

	for l in lines:

		if 'has member:' in l:

			if '\\' not in l:
				continue

			res = regex_members.search(l)
			grp, rid, obj = res.groups()
			grp = grp.replace("'\\''", "'")
			rid = int(rid)
			dom, obj = obj.split('\\', 2)
			dom = dom.upper()

			if dom == 'NT AUTHORITY':
				continue

			if dom != dom_short:
				dom_short, dom_long, dom_id = handle_domains(dom_short)

			if user_to_rid.has_key(obj):
				account_id = user_to_rid[obj]
				is_group = False

			elif group_to_rid.has_key(obj):
				account_id = group_to_rid[obj]
				is_group = True

			elif obj.endswith('$'):
				# this is a mchine account
				# TODO: handle this
				continue

			else:
				# We couldn't find the rid
				# Treat the account like a user
				account_id = 0
				is_group = False
				continue

			idx = hex(int('%d%d%d' % (dom_id, account_id, rid)))[2:]
			members.append((idx, dom_id, account_id, rid, is_group))

	return users, groups, members

def update_accounts(file):

	print "[+] Reading file..."
	users, groups, members = parse_enum(file)

	print "[+] Updating database..."

	res_u = cfg.cursor.executemany("INSERT OR REPLACE INTO domain_accounts (rid, domain_id, username, password, lm_hash, nt_hash, name, descr) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", users.values())
	print "[+] %d user accounts updated." % res_u.rowcount

	res_g = cfg.cursor.executemany("INSERT OR REPLACE INTO domain_groups (rid, domain_id, name) VALUES(?, ?, ?)", groups.values())
	print "[+] %d unique groups updated." % res_g.rowcount

	res_m = cfg.cursor.executemany("INSERT OR REPLACE INTO group_members (idx, domain_id, account_id, group_id, is_group) VALUES(?, ?, ?, ?, ?)", members)
	print "[+] %d group memberships updated." % res_m.rowcount

	cfg.cursor.commit()
	print "[+] Done."

def handle_domains(dom_str=''):

	dom_str = dom_str.upper()

	if dom_str == '':
		dom_short = raw_input("Short name for the new domain? ").upper()
		dom_long = raw_input("Domain FQDN for '%s'? " % dom_short).upper()

	elif '.' in dom_str:

		dom_long = dom_str
		for dom_id, d in cfg.domain_list.iteritems():
			if dom_str in d[1].split(', '):
				return d[0], dom_long, dom_id

		dom_short = raw_input("Short name for '%s'? " % dom_str).upper()

	else:

		dom_short = dom_str
		for dom_id, d in cfg.domain_list.iteritems():
			if d[0] == dom_str:
				return dom_short, d[1], dom_id

		dom_long = raw_input("Domain FQDN for '%s'? " % dom_str).upper()


	domain_exists = cfg.cursor.execute('SELECT id, domain, fqdn FROM domains WHERE domain = ?', (dom_short, )).fetchone()

	if domain_exists:
		dom_long = domain_exists[2] +', '+ dom_long
		cfg.cursor.execute("UPDATE domains SET fqdn = ? WHERE domain = ?", (dom_long, dom_short))
		insert_id = domain_exists[0]

	else:
		res = cfg.cursor.execute("INSERT INTO domains(domain, fqdn) VALUES(?, ?)", (dom_short, dom_long))
		insert_id = res.lastrowid

	cfg.cursor.commit()
	cfg.domain_list[insert_id] = (dom_short, dom_long)

	return dom_short, dom_long, insert_id

def get_cleartexts():

	# Getting previously cracked passwords from john.pot
	print "[+] Reading cracked passwords..."
	cfg.pot_file  = os.path.join(cfg.binder_dir, 'john.pot')

	cleartexts = {}
	cracked  = run(cfg.jtr_path + ' --format=LM --pot=%s --show %s' % (cfg.pot_file, file.name))
	cracked += run(cfg.jtr_path + ' --format=NT --pot=%s --show %s' % (cfg.pot_file, file.name))

	for l in map(sanitize, cracked.split('\n')):

		if ':::' not in l: continue
		tab = l.split(':')

		# special case when there is a ':' in the password
		while len(tab) > 8:
			tab[1] += ':'+tab[2]; del tab[2]

		if len(tab[1]) > 0 and '???????' not in tab[1]:
			cleartexts[tab[4]] = tab[1]

	return cleartexts

def update_hashes(file):

	res = -1

	if len(cfg.domain_list):
		choices = cfg.domain_list.keys() + [max(cfg.domain_list.keys()) + 1]
	else:
		choices = [1]

	while res not in choices:

		for dom_id, d in cfg.domain_list.iteritems():
			print "[%d] %s" % (dom_id, d[0])
		print "[%d] New domain" % (max(choices))
		print

		try:
			res = int(raw_input('Which domain is this for? ').strip())

		except KeyboardInterrupt:
			clean_exit(0)

		except:
			continue

	if res == max(choices):
		curr_dom, dom_long, dom_id = handle_domains()
	else:
		curr_dom, dom_long = cfg.domain_list[res]
		dom_id = res

	# Get previously cracked passwords
	cleartexts = get_cleartexts()

	# Reading pwdump file
	lines = file.readlines()
	lines = map(sanitize, lines)

	users = get_users(dom_id)

	for l in lines:

		if ':::' not in l or '$' in l: continue

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

		password = cleartexts[nt_hash] if nt_hash in cleartexts else None

		if '\\' in uname:
			dom_extract, uname = uname.split('\\')
			#dom_short, dom_long, dom_id = handle_domains(dom_extract)

		if rid in users:
			users[rid] = (rid, dom_id, uname, password, lm_hash, nt_hash, users[rid][6], users[rid][7])
		else:
			users[rid] = (rid, dom_id, uname, password, lm_hash, nt_hash, None, None)

	print "[+] Updating database..."
	res_u = cfg.cursor.executemany("INSERT OR REPLACE INTO domain_accounts (rid, domain_id, username, password, lm_hash, nt_hash, name, descr) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", users.values())
	print "[+] %d user accounts updated." % res_u.rowcount

	if len(cleartexts):
		print "[+] %d unique cleartexts." % len(cleartexts)

	cfg.cursor.commit()
	print "[+] Done."

def flush():
	print "[+] Flushing user accounts from database..."
	cfg.cursor.execute('DELETE FROM `domain_accounts`')
	cfg.cursor.execute('DELETE FROM `domain_groups`')
	cfg.cursor.execute('DELETE FROM `group_members`')
	cfg.cursor.execute('DELETE FROM `domains`')
	cfg.cursor.commit()
	print "[+] Done."

def group_members(grpname):

	def recurse(group_id, lvl):

		hdr = '|   '*lvl
		group_name = color(cfg.domain_list[dom_id][0] + '\\' + group_tree[group_id][0], 2, 1)
		print hdr + ('\\_ Sub-' if lvl > 0 else '') + "Group {} ({}):".format(group_name, group_id)

		members = cfg.cursor.execute("""
			SELECT m.account_id, m.group_id, m.is_group, g.name, d.domain, a.username, a.password, a.name, a.descr
			FROM group_members AS m
			LEFT JOIN domain_groups AS g ON (g.rid = m.group_id AND g.domain_id = m.domain_id)
			LEFT JOIN domain_accounts AS a ON (a.rid = m.account_id AND a.domain_id = m.domain_id)
			LEFT JOIN domains AS d ON (d.id = m.domain_id)
			WHERE m.group_id = ? AND m.domain_id = ? AND m.is_group = 0
			ORDER BY m.is_group ASC, m.account_id ASC
		""", (group_id, dom_id)).fetchall()

		for member in members:

			username = color(member[4] + '\\' + member[5], 3)
			password = '' if not member[6] else color(member[6], 6, 1)
			fullname = color(member[7], 4)

			print "%s|   + User: %s (%d) %s %s" % (hdr, username, member[0], fullname, password)

		for subgroup in group_tree[group_id][1]:

			if subgroup not in seen_subgroups:
				seen_subgroups.append(subgroup)
				recurse(subgroup, lvl+1)

	for dom_id in cfg.domain_scope:

		group_tree = group_hierarchy(dom_id)
		seen_subgroups = []

		root_group = cfg.cursor.execute('SELECT rid, name FROM domain_groups WHERE domain_id = ? AND LOWER(name) = ?', (dom_id, grpname.lower(),)).fetchone()

		if not root_group:
			continue

		root_group_id, root_group_name = root_group
		recurse(root_group_id, 0)

def get_user_info(username):

	if '\\' in username: # we specified the domain in the username instead of with -d
		dom, usr = username.split('\\')
		usr = usr.upper()
		dom_id = domain_id_from_name(dom)
		res = cfg.cursor.execute("SELECT * FROM domain_accounts WHERE domain_id = ? AND (UPPER(`username`) = ? OR UPPER(`name`) = ?)", (dom_id, usr, usr,))

	else:
		usr = username.upper()
		res = cfg.cursor.execute("SELECT * FROM domain_accounts WHERE (UPPER(`username`) = ? OR UPPER(`name`) = ?) AND `domain_id` IN(%s)" % ','.join(map(str, cfg.domain_scope)), (usr, usr))

	return res.fetchall()

def group_hierarchy(dom_id):
	groups = {}

	res = cfg.cursor.execute("""
		SELECT g.rid, g.name, GROUP_CONCAT(m.account_id) AS member_group_ids 
		FROM domain_groups AS g
		LEFT JOIN group_members AS m ON (m.group_id = g.rid AND m.domain_id = g.domain_id AND m.is_group=1)
		WHERE g.domain_id = ?
		GROUP BY g.rid""", (dom_id,)).fetchall()

	for row in res:
		groups[row[0]] = (row[1], map(int, row[2].split(',')) if row[2] else [])

	return groups

def get_user(username):

	users_info = get_user_info(username)

	if not users_info:
		print "[!] User not found."
		clean_exit()

	for user_info in users_info:
		print "Username : %s\\%s" % (cfg.domain_list[user_info[1]][0], user_info[2])
		print "Password : %s" % '(unknown)' if not user_info[3] else user_info[3]
		print "Real Name: %s" % user_info[6]
		print "Descript : %s" % user_info[7]
		print "Hash     : %s:%d:%s:%s:::" % (user_info[2], user_info[0], user_info[4], user_info[5])

		grps = cfg.cursor.execute("""
			SELECT rid, name FROM domain_groups
			LEFT JOIN group_members ON (group_members.group_id = domain_groups.rid)
			WHERE group_members.account_id = ? AND domain_groups.domain_id = ?
			ORDER BY domain_groups.name ASC
			""", (user_info[0], user_info[1])).fetchall()

		print
		print color("[+]", 2, 1), "First Degree Group Memberships:"
		print

		direct_groups = []
		for grp in grps:
			if grp[0] not in direct_groups:
				direct_groups.append(grp[0])
				print "   - %s (%d)" % (grp[1], grp[0])

		group_tree = group_hierarchy(user_info[1])
		inherited_groups = []

		def recurse(g):
			for group_id, subgroups in group_tree.iteritems():
				if g in subgroups[1] and group_id not in inherited_groups:
					inherited_groups.append(group_id)
					recurse(group_id)

		for g in direct_groups:
			recurse(g)

		if len(inherited_groups):
			print
			print color("[+]", 2, 1), "Inherited Group Memberships:"
			print

		for g in inherited_groups:
			print "   - %s (%d)" % (group_tree[g][0], g)

		print
		print "---"
		print

def screenshot():

	filename = datetime.now().strftime("%Y-%m-%d_%H.%M.%S") + '.png'

	if os.path.exists(cfg.project_dir):

		if not os.path.exists(cfg.shots_dir):
			os.mkdir(cfg.shots_dir)

		full_path = os.path.join(cfg.shots_dir, filename)
	else:
		full_path = os.path.join('/tmp', '.binder.png')

	os.popen('scrot -q 90 -s "%s"' % full_path)
	os.popen('xclip -selection clipboard -t image/png "%s"' % full_path)

def load_config():

	if not os.path.exists(cfg.config_file):
		print "[!] No project started. Start or resume a project with '%s start|resume <project_name>'." % sys.argv[0]
		clean_exit(1)

	cfg.base_dir        = os.path.join(cfg.project_dir, cfg.current_project)
	cfg.binder_dir      = os.path.join(cfg.base_dir, '.'+cfg.prog_name)
	cfg.database        = os.path.join(cfg.binder_dir, cfg.db_filename)
	cfg.shots_dir       = os.path.join(cfg.base_dir, 'screenshots')

	if not os.path.exists(cfg.database):
		print "[!] Database file not found for this project."
		clean_exit(1)

	cfg.cursor = sqlite3.connect(cfg.database)
	cfg.cursor.text_factory = str

	res = cfg.cursor.execute("SELECT id, `domain`, `fqdn` FROM domains").fetchall()
	for row in res:
		cfg.domain_list[row[0]] = (row[1], row[2])

	cfg.domain_scope = cfg.domain_list.keys()

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
		cfg.cursor.execute('CREATE TABLE domains (id INTEGER PRIMARY KEY, domain varchar(32), fqdn varchar(64))')
		cfg.cursor.execute('CREATE TABLE domain_accounts (rid INTEGER, domain_id INTEGER, username varchar(32) NULL, password varchar(32) NULL, lm_hash varchar(32) NULL, nt_hash varchar(32) NULL, name varchar(32) NULL, descr varchar(32) NULL, PRIMARY KEY (rid, domain_id))')
		cfg.cursor.execute('CREATE TABLE domain_groups (rid INTEGER, domain_id INTEGER, name varchar(32) NULL, PRIMARY KEY (rid, domain_id))')
		cfg.cursor.execute('CREATE TABLE group_members (idx varchar(16), domain_id INTEGER, account_id INTEGER, group_id INTEGER, is_group INTEGER, PRIMARY KEY (idx))')
		cfg.cursor.commit()
		cfg.cursor.close()

	print "[+] Done."

def passwd_or_hash(uname):

	if '\\' in uname:
		dom, usr = uname.split('\\')
		dom_id = domain_id_from_name(dom)

		res = cfg.cursor.execute("SELECT rid, domain_id, username, password, nt_hash "
			"FROM domain_accounts "
			"WHERE domain_id = ? "
			"AND LOWER(username)=LOWER(?) "
			"LIMIT 1", (dom_id, usr,))

	else:
		res = cfg.cursor.execute("SELECT rid, domain_id, username, password, nt_hash "
			"FROM domain_accounts "
			"WHERE LOWER(username)=LOWER(?) "
			"LIMIT 1", (uname,))

	fetch = res.fetchall()

	if len(fetch) == 0:
		print "[!] Error: user not found in database."
		clean_exit(1)

	rid, domain_id, username, password, nt_hash = fetch[0]
	print password if password != "" else nt_hash

def run(cmd):
	try:
		if cfg.verbose:
			print ""
			print color("[>] %s" % cmd, 2, 1)

		cfg.job_running = True
		process = subprocess.Popen(shlex.split(cmd), stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.STDOUT, env=os.environ.copy())
		ret = process.stdout.read()

		if cfg.verbose:
			print color("[<] %s" % ret.strip(), 2)

		cfg.job_running = False

		return ret.strip() + "\n"

	except KeyboardInterrupt:
		print ""
		os.kill(process.pid, SIGINT)
		cfg.job_running = False
		clean_exit(1)

if __name__ == "__main__":

	if len(sys.argv) == 1:
		sys.argv.append('--help')

	main()


# Binder
Binder is a script that I use to organise and browse through the data collected during internal network pentests.

### Why "binder" ?
Because finding names for software is hard.

### What does it do

- Most importantly it will make it easier to find and reuse data about Active Directory users, groups, accounts and passwords that you collect during internal networks pentests. It has the ability to generate nice reports and charts around password security and password strength statistics.

- Once you have compromised a domain, feed the script with an enum file (e.g. from "enum4linux.pl") and a ntds dump file (pwdump format). It will parse them and organise the data conveniently in a sqlite db. You can then issue commands to query the data in a convenient way.

- It will also automate and optimise password cracking on your shitty consultant's laptop. It does it by running appropriate John the Ripper commands (dictionaries, rules, masks, markov, bruteforce) and maintaining the database up to date. The masks are optimised for domain creds and the markov stats are generated against the previously cracked passwords for the project.

- It handles multiple projects which you can start, stop and resume your work on. It also handles multiple domains per project. It will create and maintain a sqlite database in each project directory.

- It will generate reports around password strength statistics for each domain.

### Getting started

First clone the repo or download the zip. My advice is create a symlink so you can call the "binder" command from whichever working directory.

`sudo ln -s /path/to/binder/binder.py /usr/local/bin/binder`

And make the script executable. On the first run, it will help you create the configuration file. You will have to input the path(s) to your base projects folder, dictionary files, john the ripper. Other configuration settings will be set automatically.

**Dependencies**
- _scrot_ for screenshots
- _john the ripper_ for password cracking

Otherwise only standard python libs.

**LDAP Import**

The script `ldif_import.py` makes it possible to populate binder's database from an Active Directory LDIF export. To generate the LDIF file, use the following ldapsearch command. It requires a non-privileged username and passowrd, a domain controller IP address, and the AD Base DN.

`ldapsearch -h <ip> -x -D <username> -w <password> -b <base DN> -E pr=1000/noprompt -o ldif-wrap=no > output.ldap`

Then, call binder as follows. It will populate the user accounts, groups, and descriptions:

`binder -l output.ldap`

Alternatively, the `ldap_import.py` script can be used standalone. It will connect and use the binder database for the active project:

`python ldif_import.py output.ldap`



**Command line arguments**
```
usage: binder [-h] [-s <project_name>] [-y] [-d <domain_name>] [-x <filename>]
              [-l <filename>] [-a <filename>] [-c [<levels> [<levels> ...]]]
              [-g <group_name>] [-f] [-p] [-z <username>] [-u <username>]
              [-S <search_term>] [-o] [-v]

binder version 2.0

optional arguments:
  -h, --help            show this help message and exit
  -s <project_name>, --start <project_name>
                        Start a new project or resume an existing project
  -y, --screenshot      Take a screenshot and save it in the project folder
  -d <domain_name>, --domain <domain_name>
                        Limit all actions to this domain. (i.e. when querying
                        information)
  -x <filename>, --update-hashes <filename>
                        Load creds into db from dump file. Provide pwdump-
                        style file
  -l <filename>, --ldif-import <filename>
                        Load user and group information from LDIF export.
                        Provide LDIF file. The LDIF file can be obtained with:
                        "ldapsearch -h <ip> -x -D <username> -w <password> -b
                        <base DN> -E pr=1000/noprompt -o ldif-wrap=no >
                        ldap.output"
  -a <filename>, --update-accounts <filename>
                        Load user and group info into db. Provide enum4linux
                        output file
  -c [<levels> [<levels> ...]], --crack [<levels> [<levels> ...]]
                        Run multiple password cracking attacks. Pass a space-
                        separated list of levels. Levels: 1: Local db, 2:
                        single, 3: dictionaries/rules, 4: markov, 5: masks, 6:
                        brute-force. Default: 1 2
  -g <group_name>, --group <group_name>
                        Return group members with usernames and passwords (if
                        cracked)
  -f, --flush           Delete user and group data from db
  -p, --passwords       Display all cracked passwords
  -z <username>, --getpass <username>
                        Output the user's password or otherwise NT hash
  -u <username>, --user <username>
                        Display all the information about a user.
  -S <search_term>, --search <search_term>
                        Search the database.
  -o, --report          Generate a report
  -v, --verbose         Enable debug messages

```

### License
Licensed under the I-don't-care do-whatever-you-want license v42.0

# Binder
Binder is a crappy script that I used to organise and browse through the data collected during internal network pentests.

### Why "binder" ?
Because finding names for software is hard.

### What is it not?
An attack tool. Although it can automate some basic network discovery.

### That sounds useless, what does it do then?

- Most importantly it will make it easier to find and reuse data about Active Directory users, groups, accounts and passwords that you collect during internal networks pentest.

- Once you have compromised a domain, feed the script with and enum file (e.g. from "enum4linux.pl" and a ntds dump file (pwdump format). It will parse them and organise the data conveniently in a sqlite db. You can then issue commands to query the data in a convenient way.

- It will also automate and optimise password cracking on your shitty consultant's laptop. It does it by running appropriate John the Ripper commands (dictionaries, rules, masks [todo: markov, bruteforce]) and maintaining the database up to date.

- It handle multiple projects which you can start, stop and resume your work on. It also handle multiple domains per project. It will create and maintain a sqlite database in each project directory.

- It will generate (text) reports around password strength statistics for each domain.

### Getting started

If after reading the very convincing description above you still want to give it a try. clone the repo or download the zip. My advice is create a symlink so you can call the "binder" command from whichever working directory.

`sudo ln -s /path/to/binder/binder.py /usr/local/bin/binder`

And make the script executable. On the first run, it will help you create the configuration file. You will have to input the path(s) to your base projects folder, dictionary files, john the ripper. Other configuration settings will be set automatically.

**Dependencies**
- _scrot_ for screenshots
- _john the ripper_ for password cracking

Otherwise only standard python libs.

**Command line arguments**
```
  -s <project_name>, --start <project_name>
                        Start a new project under the projects directory
  -r <project_name>, --resume <project_name>
                        Continue to work on a previously started project
  -y, --screenshot      Take a screenshot and save it in the project folder
  -d, --discover        Run discovery phase tests
  -x <filename>, --update_hashes <filename>
                        Load creds into db from dump file. Provide pwdump-style file
  -a <filename>, --update_accounts <filename>
                        Load user and parser info into db. Provide enum4linux output file
  -c <level>, --crack <level>
                        Run multiple password cracking attacks. Levels: 1:
                        single, 2: dictionaries/rules, 3: masks, 4: markov, 5:
                        brute-force. Default: 2
  --reset               Reset the password cracking status (if adding more
                        hashes for the next run)
  -g <group_name>, --group <group_name>
                        Return group members with usernames and passwords (if cracked)
  -f, --flush           Delete user and parser data from db
  -p, --passwords       Display all cracked passwords
  -m <domain_name>, --setdom <domain_name>
                        Change the active domain
  -t <table_name>, --view <table_name>
                        Dump the contents of a database table
  -z <username>, --getpass <username>
                        Output the user's password or otherwise NT hash (for reusing in other commands)
  -u <username>, --username <username>
                        Display all the information about a user.
  -o, --report          Generate a report
  -v, --verbose         Enable debug messages
```

### License
Licensed under the I-don't-care do-whatever-you-want license v42.0

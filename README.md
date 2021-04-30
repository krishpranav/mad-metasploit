# mad-metasploit
metasploit custom modules, plugins, resource script and awesome metasploit collection

[![forthebadge](https://forthebadge.com/images/badges/made-with-ruby.svg)](https://forthebadge.com)


# Download/Install
- 1 - Download module from github

- 2 - edit module to read the description

- 3 - port module to metasploit database

- 4 - reload metasploit database ..

```
service postgresql start
msfdb reinit
msfconsole -q -x 'db_status; reload_all'
```

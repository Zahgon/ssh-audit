VERSION = 'v3.9.0'

SSH_HEADER = 'SSH-{0}-OpenSSH_10.3'

GITHUB_ISSUES_URL = 'https://github.com/jtesta/ssh-audit/issues'

BUILTIN_MAN_PAGE = ''

SNAP_PACKAGE = False

SNAP_PERMISSIONS_ERROR = 'Error while accessing file.  It appears that ssh-audit was installed as a Snap package.  In that case, there are two options:  1.) only try to read & write files in the $HOME/snap/ssh-audit/common/ directory, or 2.) grant permissions to read & write files in $HOME using the following command: "sudo snap connect ssh-audit:home :home"'

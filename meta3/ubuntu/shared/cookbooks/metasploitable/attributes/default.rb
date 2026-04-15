#
# Cookbook:: metasploitable
# Attributes:: default
#
default[:metasploitable][:docker_users] = ['boba_fett',
                                           'jabba_hutt',
                                           'greedo',
                                           'chewbacca',]

# Patched: was '/vagrant/chef/cookbooks/metasploitable/files/'
default[:metasploitable][:files_path] = '/cookbooks/metasploitable/files/'

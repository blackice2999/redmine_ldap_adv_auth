require 'redmine'
require 'account_controller_patch'
require 'settings_controller_patch'

Redmine::Plugin.register :redmine_ldapadvancedauth do
  name 'LDAP Advanced Authentication for Redmine'
  author 'whqcd.org'
  description 'Plugin for LDAP user and group authentication.  Has option to have new users automatically switch to this authentication method.'
  version '0.1.0'

  classname="AuthSourceLdapAdvanced"

  settings :default => {
      'host0' => '(domaincontroller)',
      'account' => '(accountDN)',
      'password' => '(accountPassword)',
      'base_dn' => '(baseSearchDN)',
      'port' => 0,
      'attr_login' => 'samaccountname',
      'attr_first' => 'givenName',
      'attr_last' => 'sN',
      'attr_mail' => 'mail',
      'onthefly' => 1,
      'tls' => 0
  }, :partial => 'settings/ldapadvanced_settings'

  
  auth_source=AuthSource.find_by_type(classname)

  if auth_source.nil?
      auth_source=AuthSource.create({:name=>"ldap-adv-auth"})
      auth_source.type=classname;
      auth_source.save
      Rails.logger.info "#{classname} auth source created."
  end
end

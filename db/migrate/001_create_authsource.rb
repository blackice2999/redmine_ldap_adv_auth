class CreateAuthsource < ActiveRecord::Migration
  def self.up
    classname="AuthSourceLdapAdvanced"
    auth_source=AuthSource.find_by_type(classname)
    if auth_source.nil?
        auth_source=AuthSource.create({:name=>"ldap-adv-auth"})
        auth_source.type=classname
        auth_source.save
    end
  end

  def self.down
    auth_source=AuthSource.find_by_type("AuthSourceLdapAdvanced")
    if !auth_source.nil?
        AuthSource.remove({:name=>"ldap-adv-auth"})
    end
  end

end

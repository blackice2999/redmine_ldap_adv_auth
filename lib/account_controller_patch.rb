module AccountControllerPatch
    def self.included(base)
        base.send(:include, InstanceMethods)
        base.class_eval do
            alias_method_chain :register, :auth_source
            alias_method_chain :authenticate_user, :auth_source
        end
    end

    module InstanceMethods
        def authenticate_user_with_auth_source
            if !(Setting['plugin_redmine_ldapadvancedauth']['onthefly']=="true")
                authenticate_user_without_auth_source
                return
            end

            # check if the user signing in is already in the database
            # if nothing returns, see if the user is in LDAP
            user=User.find_by_login(params[:username])
            if user.nil?
                auth_source=AuthSource.find_by_type('AuthSourceLdapAdvanced')
                auth_id=auth_source.id

                # try to authenticate with the users' credentials
                # if something comes back - it indicates the user exists
                # get the users' attributes and populate them
                # and register the user
                attribs=auth_source.authenticate(params[:username], params[:password], true)
                if attribs
                    user=User.new(attribs)
                    user.login=params[:username]
                    user.language=Setting.default_language
                    user.auth_source_id=auth_id
                    onthefly_creation_failed(user, {:login=>user.login, :auth_source_id => auth_id})
                else
                # if nothing comes back, either onthefly creation is not on
                # or the users' authentication failed
                    authenticate_user_without_auth_source
                end
            else
            # if there is a user in the db
            # go through the normal route
                authenticate_user_without_auth_source
            end
        end

        def register_with_auth_source
            register_without_auth_source

            if !request.get?
                # check if automatically switch registerd users to this method is checked
                if !(Setting['plugin_redmine_ldapadvancedauth']['auto_register']=="true")
                    return
                end

                # make sure the auth id is set to ldap full method
                # check if the user is in ldap by looking up the name
                # through AuthSourceLdapFull class
                # if it is not in ldap, let user through with no auth method
                # which will allow it to be local in redmine
                # Note: this can be configured in the view
                auth_source=AuthSource.find_by_type("AuthSourceLdapAdvanced")
                auth_id=auth_source.id
                result=auth_source.check_user_in_ldap(@user.login)
                if result
                    @user.auth_source_id=auth_id
                    @user.save
                else
                    logger.info "#{@user.login} is not a member of LDAP"
                end
            end
        end
    end
end

AccountController.send(:include, AccountControllerPatch)

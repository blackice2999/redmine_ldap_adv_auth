module SettingsControllerPatch
    def self.included(base)
        base.send(:include, InstanceMethods)
        base.class_eval do
            alias_method_chain :plugin, :password_check 
        end
    end

    module InstanceMethods
        def plugin_with_password_check
            # attempt to intercept check
            # we do not want to expose the password
            # in the plain html 
            # therefore, a placeholder is put into the password
            # this will check to make sure that if there is no password element
            # the password will not be cleared out from the settings value
            @plugin=Redmine::Plugin.find(params[:id])

            notice=""

            if @plugin.id == :redmine_ldapadvancedauth && request.post?
                if params[:settings]['password'].nil?
                    params[:settings]['password']=Setting["plugin_#{@plugin.id}"]['password']
                end


                # check the fields input into the settings
                # this will ensure that we get what was asked
                id=0
                while 1
                    host=params[:settings]["host#{id}"]
                    break if host.nil?

                    if host.empty?
                        params[:settings].delete("host#{id}") if id != 0 # do not remove the 0th element
                        notice += "host#{id} cannot be empty<br />"
                        break
                    end
                    id +=1
                end

                # check other standard fields to make sure
                # they are not empty
                fields={
                    "account"=>"Account DN", "base_dn"=>"Base DN", "attr_first"=>"Login name field", 
                    "attr_last"=>"Last name field", "attr_first"=>"First name field", "attr_mail"=>"Mail field"
                }

                fields.keys.each { |f|
                    if (params[:settings][f]).empty?
                        notice += "<b>#{fields[f]}</b> cannot be empty<br />"
                    end
                }

                if (params[:settings]["use_recommended_port"]).nil? && (params[:settings]["port"]).empty?
                    notice += "<b>Port</b> cannot be empty<br />"
                end


                Setting["plugin_#{@plugin.id}"]=params[:settings]

                if !notice.empty?
                    flash[:error]="There were errors found in the data: <br />#{notice}"
                    redirect_to :action=>'plugin', :id=>@plugin.id
                    return
                end
            end

            plugin_without_password_check
        end
    end
end

SettingsController.send(:include, SettingsControllerPatch)

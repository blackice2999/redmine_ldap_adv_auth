# redmine - LDAP group authentication - link with redmine role groups
# Copyright 2011 whqcd.org
#
# NOTE: ldap search will fail if when finding users the base_dn is set to root
#       Therefore, please remember to set to CN=Users,...
# 
# Protocols
# SSL (Secure Socket Layer)
# -------------------------
# in order for SSLConn to work a pem file must be defined in the /etc/ldap/ldap.conf file
# TLS_CACERT [path_to_file]
#
# TLS (Transport Layer Security)
# ------------------------------
# please remember, that TLS does not use the SSL port
# the default port is 389 for TLS

require 'ldap'
require 'iconv'

class AuthSourceLdapAdvanced < AuthSource
    validates_presence_of :name

    $conn=nil

    # get_setting
    # retrieves the settings for the plugin
    # usage: get_setting(array)
    # items: :port, :hosts, :protocol, :account, :password, :base_dn, 
    #        :attr_login, :attr_first, :attr_last, :attr_mail, :onthefly
    # if only one item is specified, a scalar value will be returned
    
    def get_setting(item)
        setting=Setting['plugin_redmine_ldapadvancedauth']

        values={}
        item.each { |i|
            case "#{i}"
            when "port"
                values[:port]=setting['port'] ? setting['port'].to_i : (setting['protocol']=="SSL" ? LDAP::LDAPS_PORT : LDAP::LDAP_PORT)
            when "hosts"
                values[:hosts]=[]
                id=0
                while 1
                    name=setting["host#{id}"]
                    break if name.nil?
                    values[:hosts].push(name)
                    id +=1
                end
            when "protocol"
                values[:protocol]=setting['protocol']
            when "account"
                values[:account]=setting['account']
            when "password"
                values[:password]=setting['password']
            when "base_dn"
                values[:base_dn]=setting['base_dn']
            when "attr_login"
                values[:attr_login]=setting['attr_login']
            when "attr_first"
                values[:attr_first]=setting['attr_first']
            when "attr_last"
                values[:attr_last]=setting['attr_last']
            when "attr_mail"
                values[:attr_mail]=setting['attr_mail']
            when "onthefly"
                values[:onthefly]=setting['onthefly']
            end
        }

        if item.length > 1
            return values
        else
            values.keys.each { |i|
                return values[i]
            }
        end
    end

    # eval_bind_result
    # evalutes result of the LDAP bind
    # returns : true, false, or nil
    def eval_bind_result(r)
        return false if r==2
        return true if r != 1 && r != 2
    end

    # get_and_bind_connection()
    # creates a connection and binds
    # returns
    # 0x1 : cannot connect to server
    # 0x2 : invalid credentials
    # connection, if sucessful
    #
    # usage: get_and_bind_connection([hash] options)
    # options: :protocol, :host, :port, :account, :password
    def get_and_bind_connection(o)
        c=nil
        begin
            if o[:protocol] == "SSL" || o[:protocol] == "TLS"
                logger.info "attempt connection on #{o[:host]}, port: #{o[:port]}, protocol: #{o[:protocol]}"
                c=LDAP::SSLConn.new(o[:host], o[:port], o[:protocol]=="TLS" ? true : false)
            else
                logger.info "attempt connection on #{o[:host]}, port: #{o[:port]}"
                c=LDAP::Conn.new(o[:host], o[:port])
            end

            c.bind(o[:account],o[:password])
            c.perror('bind')
        rescue LDAP::ResultError => result
            logger.info "Error in get and bind: #{result}.  Host: #{o[:host]}, Port:#{o[:port]}, Protocol:#{o[:protocol]}"
            return "#{result}" == "Invalid credentials" ? 0x2 : 0x1
        end              
        c
    end

    # initialize_conn
    # creates the global connection object that will be used
    # for other requests with LDAP
    # usage: initialize_conn()
    # returns: true, false
    def initialize_conn
        options=get_setting([:account,:password,:port,:protocol])
        get_setting([:hosts]).each { |h|
            $conn=get_and_bind_connection(options.merge({:host=>h}))
            r=eval_bind_result($conn)
            return r if !r.nil?
        }
        false
    end

    # authenticate_user()
    # attempts to authenticate a user and return
    # true or false if it was successful or not
    def authenticate_user(dn,password)
        if dn.present? && password.present?
            temp=nil
            options=get_setting([:protocol,:port])
            get_setting([:hosts]).each { |h|
                temp=get_and_bind_connection(options.merge({:host=>h, :account=>dn, :password=>password}))
                r=eval_bind_result(temp)
                return r if !r.nil?
            }
        end
        false
    end

    def check_user_in_ldap(login)
        s=get_setting([:account,:password,:port,:protocol,:base_dn])

        temp=nil
        have_conn=false
        get_setting([:hosts]).each { |h|
            temp=get_and_bind_connection(s.merge({:host=>h}))
            r=eval_bind_result(temp)
            if r==true
                have_conn=true
                break
            end
        }

        return false if !have_conn

        logger.info "Finding if #{login} is in active directory"

        inldap=false
        temp.search(s[:base_dn], LDAP::LDAP_SCOPE_SUBTREE, "(samaccountname=#{login})", ['dn']) { |g|
            logger.info "#{login} found in active directory"
            inldap=true
            break
        }
        temp.unbind
        temp=nil
        inldap
    end

    def authenticate(login,password,forRegister=false)
        result=initialize_conn()
        return nil if result==false
        return nil if login.blank? || password.blank?
        values = get_user_dn(login)

        if values[:disabled]
            logger.info "#{login} is disabled.  Authentication failed."
            return false
        end

        # test if the user can be authenticated
        if values && values[:dn] && authenticate_user(values[:dn],password)
            if !forRegister
                # if there was a succesful logon
                # get the users' groups and
                # match with existing role groups
                groups = get_token_groups(values[:dn])

                user=User.find_by_login(login)

                # go through each group
                # and match it with a ad group
                # see if the user is part of the group
                Group.all.each { |g|
                    # see if user is member of group
                    is_member=is_redmine_group_member(login,g)
                    name=g.name

                    # if user is member of AD group
                    # and not member of redmine group
                    # add into the redmine group object
                    g.users << user if groups.key?(name) && !is_member

                    # if the user is member of redmine group
                    # and not member of AD group
                    # remove from redmine group object
                    g.users.delete(user) if !groups.key?(name) && is_member && is_redmine_group_in_ldap(name)
                }


            end

            close_connection()
            return values.except :dn,:disabled
        end

        close_connection()
        return nil
    end

    def is_redmine_group_in_ldap(group)
        $conn.search(get_setting([:base_dn]), LDAP::LDAP_SCOPE_SUBTREE, "(cn=#{group})", ['dn']) { |g|
            return true
        }
        return false
    end

    def is_redmine_group_member(login,group)
        group.users.each{ |u|
            return true if u.login==login
        }
        return false
    end


    def test_connect
        values=get_setting([:account,:password])
        authenticate_user(values[:account],values[:password])
    end


    def auth_method_name
        "LDAP-Advanced-Authentication"
    end

    def get_attribute(entry,attrib)
        if !attrib.blank?
            entry.vals(attrib).is_a?(Array) ? entry.vals(attrib).first : entry.vals(attrib)
        end
    end

    # get_user_dn()
    # retrieves the users' information
    #   onthefly => :dn, :firstname, :lastname, :mail
    #   other    => :dn
    # get_user_dn([string]login)
    # usage: get_user_dn(samaccountname)
    def get_user_dn(login)
        returns={}
        options=get_setting([:base_dn,:onthefly,:attr_login,:attr_first,:attr_last,:attr_mail])
        onthefly=options[:onthefly]=="true" ? true : false

        $conn.search(options[:base_dn], LDAP::LDAP_SCOPE_SUBTREE, "(#{options[:attr_login]}=#{login})", ['dn', options[:attr_login], options[:attr_first], options[:attr_last], options[:attr_mail], 'useraccountcontrol']) { |user|
            if onthefly
                returns={
                    :login=>get_attribute(user,options[:attr_login]),
                    :dn=>user.dn,
                    :firstname=>get_attribute(user, options[:attr_first]),
                    :lastname=>get_attribute(user, options[:attr_last]),
                    :mail=>get_attribute(user, options[:attr_mail]),
                    :disabled=>("#{get_attribute(user, 'useraccountcontrol')}".to_i & 0x2) == 0x2 ? true : false
                }
            else
                returns={:dn=>user.dn, :disabled=>("#{get_attribute(user, 'useraccountcontrol')}".to_i & 0x2) == 0x2 ? true : false}
            end
        }

        returns
    end

    # get_token_groups()
    # retrieves the groups a user or object is a member of
    # usage: get_token_groups([string] distinguishedName)
    # 
    def get_token_groups(dn)
        groups={}
        $conn.search(dn,LDAP::LDAP_SCOPE_BASE,'(objectCategory=*)', ['tokenGroups']) { |item|
            tokens=item.vals('tokenGroups')
            tokens.each{ |token| 
                r=get_group_name(token.unpack('H*'))
                groups[r]=0 if !r.nil?
            }
        }
        groups
    end

    # get_group_name()
    # get the group name from SID string.  Used along with get_token_groups
    # usage: get_group_name([string] sid)
    # returns the cn of the group

    def get_group_name(sid)
        begin
            $conn.search("<SID=#{sid}>",LDAP::LDAP_SCOPE_BASE,'(objectCategory=*)',['samaccountname','cn']){ |item|
                return "#{item['cn']}"
            }
        # this fails if there is an orphaned SID
        # the rescue statement will prevent from failing fully
        rescue LDAP::ResultError => text
        end
    end

    def close_connection
        $conn.unbind
        $conn=nil
    end

end

cookbook_file '/etc/yum.repos.d/logstash.repo' do
    source 'logstash.repo'
    mode 0644

end



cookbook_file '/etc/pki/tls/openssl.cnf' do
    source 'openssl.cnf'
    mode 0644

end

cookbook_file '/etc/pki/tls/certs/logstash-forwarder.crt' do
    source 'logstash-forwarder.crt'
    mode 0644

end



cookbook_file '/etc/pki/tls/certs/logstash-forwarder.crt' do
    source 'logstash-forwarder.crt'
    mode 0644

end



cookbook_file '/etc/logstash/conf.d/input.conf' do
    source 'input.conf'
    mode 0644

end


cookbook_file '/etc/logstash/conf.d/output.conf' do
    source 'output.conf'
    mode 0644

end



cookbook_file '/etc/logstash/conf.d/filter.conf' do
    source 'filter.conf'
    mode 0644

end

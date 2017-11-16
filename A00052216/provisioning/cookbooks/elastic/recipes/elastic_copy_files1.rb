cookbook_file '/etc/elasticsearch/elasticsearch.yml' do
    source 'elasticsearch.yml'
    mode 0644

end
#!/bin/bash
cat domains.txt | while read domain ;
do
        [[ $domain = \#* ]] && continue
        domain=$(awk '{ print tolower($0) }' <<< $domain)
        dig +short -t ns $domain | while read line ;
        do
               dig +short -t a $line | grep '^[.0-9]*$' | while read ip ;               
               do
                       fqdn=$(sed 's/\.$//' <<< $line)
                       if [[ $fqdn =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]]; then
                           fqdn=""
                       fi
                       echo "{\"fqdn\":\"$fqdn\",\"ip\":\"$ip\",\"ns\":\"domain\",\"domain\":\"$domain\"}"
               done
        done
done


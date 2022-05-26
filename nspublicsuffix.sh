#!/bin/bash

curl -s https://publicsuffix.org/list/public_suffix_list.dat -o public_suffix_list.dat

cat public_suffix_list.dat | while read tld ;
do
        [[ $tld = //* ]] && continue
        [[ -z "${tld}" ]] && continue

        tld=$(awk '{ print tolower($0) }' <<< $tld)
        dig +short -t ns $tld | while read line ;
        do
               dig +short -t a $line | while read ip ;
               do 
                   fqdn=$(sed 's/\.$//' <<< $line)              
                   echo "{\"fqdn\":\"$fqdn\",\"ip\":\"$ip\",\"ns\":\"tld\",\"tld\":\"$tld\"}"
               done
        done
done


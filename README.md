1. Парсинг eve.json:
   echo 'timestamp,src_ip,dest_ip,signature' > ./timestamps_filenames.csv
   cat ./eve.json | jq -r 'select(.alert.severity == 1) | "\(.timestamp),\(.src_ip),\(.dest_ip),\(.alert.signature)"' >> ./all_signature.csv

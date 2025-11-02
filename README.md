1. Парсинг eve.json:
   echo 'timestamp,src_ip,dest_ip,signature' > ./timestamps_filenames.csv
   cat ./eve.json | jq -r 'select(.alert.severity == 1) | "\(.timestamp),\(.src_ip),\(.dest_ip),\(.alert.signature)"' >> ./all_signature.csv
Запускаем скрипт, который на выходе даст csv файл с src_ip, dst_ip, signature, filename, в котором сработала сигнатура
Запускаем скрипт, который сгруппирует по сигнатуре и src_ip
 Если будут ошибки нужно заполнить пустую ячейку в конце чем угодно.

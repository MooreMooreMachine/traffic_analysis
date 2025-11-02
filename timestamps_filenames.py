import pyshark  
import os  
import sys  
import datetime  
import csv  
import argparse  
  
  
def absolute_path_generator(root_path):  
    for root, _, filenames in os.walk(root_path):  
        for filename in filenames:  
            absolute_file_path = os.path.join(root, filename)  
            yield absolute_file_path  
  
#Открывает каждый .cap файл. Извлекает из первого пакета атрибут  
# frame_info.time и заполняет список result списками ['filename.cap', 'timestamp']  
def generate_filename_timestamps_list(traffic_root_folder):  
    result = []  
    for i, pth in enumerate(absolute_path_generator(traffic_root_folder)):  
        traf_file_params = []  
        traf_file_params.append(os.path.basename(pth))  
        print(f'Now working with {os.path.basename(pth)}....')  
        capture = pyshark.FileCapture(pth)  
        try:  
            if hasattr(capture[0], 'frame_info'):  
                ts = capture[0].frame_info.time  
                traf_file_params.append(ts)  
        except:  
            pass  
        capture.close()  
        result.append(traf_file_params)  
    # Дополняет вложенные списки списка result временной меткой следующего пакета  
    listed_result = []  
    for i, v in enumerate(result):  
        try:  
            v.append(result[i + 1][1])  
        except IndexError:  
            v.append(result[i][1])  
        listed_result.append(v)  
    return listed_result  
  
def create_final_csv(suricata_csv_file, filenames_timestamps_list, output_csv_file):  
    with open(suricata_csv_file, newline='') as csvfile:  
        reader = csv.DictReader(csvfile)  
        listed_dataset = []  
        for row in reader:  
            row_list = []  
            row_list.append(row['src_ip'])  
            row_list.append(row['dest_ip'])  
            row_list.append(row['signature'])  
            dt_check = datetime.datetime.fromisoformat(row['timestamp'])  
            for ts in filenames_timestamps_list:  
                try:  
                    dt_left = datetime.datetime.fromisoformat(ts[1])  
                    dt_right = datetime.datetime.fromisoformat(ts[2])  
                    if dt_left <= dt_check <= dt_right:  
                        if len(row_list) == 4:  
                            continue  
                        else:  
                            row_list.append(ts[0])  
                except:  
                    pass  
            listed_dataset.append(row_list)  
        csvfile.close()  
    with open(output_csv_file, 'w', newline='') as csv_writer:  
        writer = csv.writer(csv_writer)  
        writer.writerow(["src_ip", "dest_ip", "signature", "filename"])  
        for row in listed_dataset:  
            writer.writerow(row)  
        csv_writer.close()  
  
parser = argparse.ArgumentParser(add_help=True, description="Перед запуском скрипта нужно подготовить файл .csv с сработками suricata",  
                                 usage='%(prog)s <путь_к_папке_с_трафиком>', allow_abbrev=False)  
parser.add_argument('traffic_folder', action='store', help='папка с трафиком')  
parser.add_argument('-o', '--output', action='store', help='Итоговый csv файл')  
parser.add_argument('-s', '--suricata', action='store', help='csv с результатами парсинга eve.json')  
parser.add_argument('--version', action='version', version='%(prog)s 1.0')  
options = parser.parse_args()  
if len(sys.argv)==1:  
    parser.print_help()  
    sys.exit(1)  
folder_path = options.traffic_folder  
output_file = options.output  
suricata_eve_json_parsing = options.suricata  
  
filenames_timestamps = generate_filename_timestamps_list(folder_path)  
create_final_csv(suricata_eve_json_parsing, filenames_timestamps, output_file)

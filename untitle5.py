import csv
import os

from flask import Flask, request
from flask_restful import Resource, Api, reqparse
import sqlite3

app = Flask(__name__)

api = Api(app)

conn_string = 'sfnportalTest.db'

conn = sqlite3.connect(conn_string)
cur = conn.cursor()
#            conn.text_factory = str
cur.execute(
             """CREATE TABLE IF NOT EXISTS telus1('Domain', 'Receive Time', 'Serial #', 'Type', 'Threat/Content Type', 'Config Version', 'Generate Time', 'Source address', 'Destination address', 'NAT Source IP', 'NAT Destination IP', 'Rule', 'Source User', 'Destination User', 'Application', 'Virtual System', 'Source Zone', 'Destination Zone', 'Inbound Interface', 'Outbound Interface', 'Log Action', 'Time Logged', 'Session ID', 'Repeat Count', 'Source Port', 'Destination Port', 'NAT Source Port', 'NAT Destination Port', 'Flags', 'IP Protocol', 'Action', 'URL', 'Threat/Content Name', 'Category', 'Severity', 'Direction', 'seqno', 'actionflags', 'Source Country', 'Destination Country', 'cpadding', 'contenttype', 'pcap_id', 'filedigest', 'cloud', 'url_idx', 'user_agent', 'filetype', 'xff', 'referer', 'sender', 'subject','recipient', 'reportid', 'dg_hier_level_1', 'dg_hier_level_2', 'dg_hier_level_3', 'dg_hier_level_4', 'vsys_name', 'device_nam', 'file_url', 'Source VM UUID', 'Destination VM UUID', 'http_method', 'Tunnel ID/IMSI', 'Monitor Tag/IMEI', 'Parent Session ID','parent_start_time', 'tunnel', 'thr_category', 'contentver', 'sig_flags')""")

print "Safe Networking"
columns = [
    'Domain', 'Receive Time', 'Serial #', 'Type', 'Threat/Content Type', 'Config Version',
    'Generate Time', 'Source address', 'Destination address', 'NAT Source IP', 'NAT Destination IP',
    'Rule', 'Source User', 'Destination User', 'Application', 'Virtual System', 'Source Zone',
    'Destination Zone', 'Inbound Interface', 'Outbound Interface', 'Log Action', 'Time Logged',
    'Session ID', 'Repeat Count', 'Source Port', 'Destination Port', 'NAT Source Port',
    'NAT Destination Port', 'Flags', 'IP Protocol', 'Action', 'URL', 'Threat/Content Name',
    'Category', 'Severity', 'Direction', 'seqno', 'actionflags', 'Source Country',
    'Destination Country', 'cpadding', 'contenttype', 'pcap_id', 'filedigest', 'cloud',
    'url_idx', 'user_agent', 'filetype', 'xff', 'referer', 'sender', 'subject','recipient',
    'reportid','dg_hier_level_1', 'dg_hier_level_2', 'dg_hier_level_3', 'dg_hier_level_4',
    'vsys_name', 'device_nam', 'file_url', 'Source VM UUID', 'Destination VM UUID',
    'http_method', 'Tunnel ID/IMSI', 'Monitor Tag/IMEI', 'Parent Session ID', 'parent_start_time',
    'tunnel', 'thr_category', 'contentver', 'sig_flags'
]


def write_csv_header():
    with open('requests.csv', 'a') as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(columns)


def write_data_to_csv(request_data):
    with open('requests.csv', 'a') as csv_file:
        csv_writer = csv.writer(csv_file)
        csv_writer.writerow(request_data)


def generate_query(data):
    values = tuple(data)
    cols = tuple(columns)
    return "INSERT INTO telus1 {cols} VALUES {values};".format(cols=cols, values=values)


def check_db_contents(cur=None):
    data = None
    if cur:
        data = cur.fetchall()
        print('.' * 70)
        print(data)
        print('.' * 70)
        cur.close()
    else:
        conn = sqlite3.connect(conn_string)
        cur = conn.cursor()
        cur.execute("CREATE TABLE IF NOT EXISTS Cars (Id INT, Name TEXT, Model INT)")
        cur.execute("INSERT INTO Cars VALUES(2,'Mercedes',57127)")
        data = cur.fetchall()

        print('.' * 70)
        print(data)
        print('.' * 70)
        cur.close()
        conn.close()
    return data


check_db_contents()


class CreateRecord(Resource):
    def post(self):
        request_data = request.data.split(',')

        write_data_to_csv(request_data)
        query = generate_query(request_data)

        conn = sqlite3.connect(conn_string)
        conn.row_factory = sqlite3.Row
        cur = conn.cursor()
        cur.execute(query)
        conn.commit()

        data = check_db_contents(cur)

        if len(data) is 0:
            return {'StatusCode': '200', 'Message': 'User creation success'}
        else:
            return {'StatusCode': '1000', 'Message': str(data[0])}



api.add_resource(CreateRecord,'/CreateRecord')


@app.route('/')
def hello_world():
    return 'Safe Network API Collector - send your threat logs to http port 8808 - URI = /CreateRecord - headers = Content-Type - Value = application/json = Payload = All !'

if __name__ == '__main__':
    write_csv_header()
    app.run(host='0.0.0.0', port=8808, debug=True)

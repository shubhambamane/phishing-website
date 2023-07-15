# -*- coding: utf-8 -*-
"""
Created on Wed Apr 29 11:11:57 2020

@author: madhu
"""
import csv
import pandas as pd
import Feature_extraction as urlfeature # this will take file feature_extraction as urlfeature
import trainer as tr # this will take file train.py as tr
#print("a")

def resultwriter(feature,output_dest): # this will write all the features iin a csv file
    out=[]
    for item in feature:
        out.append(item.values())
    df = pd.DataFrame(out)    
    df.to_csv(output_dest, header = ['url','protocol','domain','subdomain','tld','fld','path','havingIP','http','longurl','atinurl','slash','hypen','dots','phishterm','shorten','httpinpath','phishtld','phishing'], index = False)
      
def process_URL_list(file_dest,output_dest):# i think this takes whole file of urls with given malicious to extract their  feature and provide malicious column also like this will take url.txt
    feature=[]
    dataset = pd.read_csv(file_dest,header=0,names=['url','Phishing'])
    a = []              # for storing urls
    output = []         # for storing phishing or not
    rows = len(dataset['url'])

    for url in dataset['url']:
        a.append(url)
    for Phishing in dataset['Phishing']:
        output.append (Phishing)
        
    c = []              
    for url1, Phishing in zip(a, output):
        url = url1
        if Phishing == 'Yes':
            malicious_bool = 1
        elif Phishing == 'No':
            malicious_bool = -1
        
        #print(url,malicious_bool)                         #showoff
        #print ('working on: '+url)                        #showoff
        ret_dict=urlfeature.feature_extract(url)
        ret_dict['Phishing']=malicious_bool
        feature.append(ret_dict);
    #print (feature)                                       #showoff
    resultwriter(feature,output_dest)

process_URL_list('test_final.csv','test_features.csv')
#process_URL_list('train_final.csv','train_features.csv')
print('Dataset is created....')


import pandas
from sklearn import preprocessing
import numpy
from sklearn import svm
from sklearn.model_selection import cross_val_score as cv
from sklearn import metrics
import matplotlib.pylab as plt
import warnings
#from sklearn.ensemble import BaggingClassifier
#from sklearn.linear_model import LogisticRegression
from sklearn.tree import DecisionTreeClassifier
from sklearn.naive_bayes import GaussianNB
from sklearn.ensemble import RandomForestClassifier
#from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import accuracy_score, classification_report,confusion_matrix 
import time
warnings.filterwarnings("ignore", category=DeprecationWarning,
                        module="pandas", lineno=570)
#from sklearn.ensemble import GradientBoostingClassifier
#from xgboost import XGBClassifier

#from xgboost import XGBClassifier
def return_nonstring_col(data_cols): # giving columns that are not string in nature like url , host, path
    cols_to_keep=[]
    train_cols=[]
    cols_to_keep = data_cols[7:18]
    train_cols = data_cols[7:18]
    return [cols_to_keep,train_cols]

def performace_parameters(matrix):
    
    TP = matrix[1, 1]
    TN = matrix[0, 0]
    FP = matrix[0, 1]
    FN = matrix[1, 0]
    print('TP: ',matrix[1, 1])
    print('TN: ',matrix[0, 0])
    print('FN: ',matrix[1, 0])
    print('FP: ',matrix[0, 1])
    print('Accuracy: ',((TP + TN) / float(TP + TN + FP + FN)))
    print('Precision: ',(TP / float(TP + FP)))
    print('Classification Error: ',((FP + FN) / float(TP + TN + FP + FN)))
    print('False Positive Rate: ',(FP / float(TN + FP)))
    print('Sensitivyty/Recall: ',(TP / float(FN + TP)))
    print('Specificity: ',(TN / (TN + FP)))
    
# Called from gui
def forest_classifier_gui(train,query,train_cols):# train is train dataset and query is test dataset and train_cols is are the columns of train dataset exclude malicious
    
    rf = RandomForestClassifier(n_estimators=150)
    print (rf.fit(train[train_cols], train['phishing']))
    query['result']=rf.predict(query[train_cols])
    print (query[['url','result']].head(2))
    
    return query['result']


def naive_classifier_gui(train,query,train_cols): # train is train dataset and query is test dataset and train_cols is are the columns of train dataset exclude malicious\
    
    clf = GaussianNB()
    print (clf.fit(train[train_cols], train['phishing']))
    query['result']=clf.predict(query[train_cols])
    print (query[['url','result']].head(2))
    
    return query['result']

def DecisionTree_Classifier_gui(train,query,train_cols): # train is train dataset and query is test dataset and train_cols is are the columns of train dataset exclude malicious\
    
    deci = DecisionTreeClassifier(random_state = 100,max_depth=3, min_samples_leaf=5)
    print (deci.fit(train[train_cols], train['phishing']))
    query['result']=deci.predict(query[train_cols])
    print (query[['url','result']].head(2))
    
    return query['result']

def DecisionTree_Classifier(train,query,train_cols): # train is train dataset and query is test dataset and train_cols is are the columns of train dataset exclude malicious
    deci = DecisionTreeClassifier(random_state = 100,max_depth=3, min_samples_leaf=5)
    print (deci.fit(train[train_cols], train['phishing']))
    scores = cv(deci, train[train_cols], train['phishing'], cv=30)
    print('Estimated score decisiontreeclassifier : %0.5f (+/- %0.5f)' % (scores.mean(), scores.std() / 2))
    query['result']=deci.predict(query[train_cols])
    #print (query[['url','result']])
    #accuracy = 100.0 * accuracy_score(query['phishing'],query['result'])
    #print('The accuracy is:', accuracy)
    print(confusion_matrix(query['phishing'],query['result']))
    confusion = confusion_matrix(query['phishing'],query['result'])
    performace_parameters(confusion)
    print(classification_report(query['phishing'],query['result']))
    #query[['url','result']].to_csv("E:/Download/vd mdr/test_predicted_target_deci.csv")
      
def forest_classifier(train,query,train_cols): # train is train dataset and query is test dataset and train_cols is are the columns of train dataset exclude malicious
    rf = RandomForestClassifier(n_estimators=150)
    print (rf.fit(train[train_cols], train['phishing']))
    scores = cv(rf, train[train_cols], train['phishing'], cv=30)
    print('Estimated score RandomForestClassifier: %0.5f (+/- %0.5f)' % (scores.mean(), scores.std() / 2))
    query['result']=rf.predict(query[train_cols])
    #print (query[['url','result']])
    #accuracy = 100.0 * accuracy_score(query['phishing'],query['result'])
    #print('The accuracy is:', accuracy)
    print (confusion_matrix(query['phishing'],query['result']))
    confusion = confusion_matrix(query['phishing'],query['result'])
    performace_parameters(confusion)
    print(classification_report(query['phishing'],query['result']))
    #query[['url','result']].to_csv("E:/Download/vd mdr/test_predicted_target_rf.csv")

def naive_classifier(train,query,train_cols): # train is train dataset and query is test dataset and train_cols is are the columns of train dataset exclude malicious
    clf = GaussianNB()
    print (clf.fit(train[train_cols], train['phishing']))
    scores = cv(clf, train[train_cols], train['phishing'], cv=30)
    print('Estimated score SVM: %0.5f (+/- %0.5f)' % (scores.mean(), scores.std() / 2))
    query['result']=clf.predict(query[train_cols])
    #print (query[['url','result']])
    #accuracy = 100.0 * accuracy_score(query['phishing'],query['result'])
    #print('The accuracy is:', accuracy)
    print (confusion_matrix(query['phishing'],query['result']))
    confusion = confusion_matrix(query['phishing'],query['result'])
    performace_parameters(confusion)
    print(classification_report(query['phishing'],query['result']))
    #query[['url','result']].to_csv("E:/Download/vd mdr/test_predicted_target_naive.csv")

def train(db,test_db):
    
    query_csv = pandas.read_csv(test_db)
    cols_to_keep,train_cols=return_nonstring_col(query_csv.columns)
	#query=query_csv[cols_to_keep]
    train_csv = pandas.read_csv(db)
    cols_to_keep,train_cols=return_nonstring_col(train_csv.columns)
    train=train_csv[cols_to_keep]
    
    start = time.time()
    naive_classifier(train_csv,query_csv,train_cols)
    #forest_classifier(train_csv,query_csv,train_cols)
    #DecisionTree_Classifier(train_csv,query_csv,train_cols)
    elapsed = time.time()-start
    print('Elapsed Timer: ',elapsed)
    	
    
def gui_caller(db,test_db):
    
    query_csv = pandas.read_csv(test_db)
    cols_to_keep,train_cols=return_nonstring_col(query_csv.columns)
    train_csv = pandas.read_csv(db)
    cols_to_keep,train_cols=return_nonstring_col(train_csv.columns)
    train=train_csv[cols_to_keep]   
    
    #return naive_classifier_gui(train_csv,query_csv,train_cols)	    
    return forest_classifier_gui(train_csv,query_csv,train_cols)
    #return DecisionTree_Classifier_gui(train_csv,query_csv,train_cols)
    
    
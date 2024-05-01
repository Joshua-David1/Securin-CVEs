from flask import Flask, request, render_template, url_for,jsonify,redirect
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import extract
from get_cve import get_cve_list, add_cve_details
from datetime import datetime
import json
from flask_apscheduler import APScheduler
scheduler = APScheduler()

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cve_details.db'
app.config['SECRET_KEY'] = 'Nothingmuch'
db = SQLAlchemy(app)


class CVE(db.Model):
    __tablename__ = "cve"
    id = db.Column(db.Integer,nullable=False,unique=True)
    cve_id = db.Column(db.String(100), nullable=False,primary_key=True)
    source_identifier = db.Column(db.String(100),nullable=False)
    published = db.Column(db.DateTime,nullable=False)
    last_modified = db.Column(db.DateTime,nullable=False)
    vuln_status = db.Column(db.String(100),nullable=False)
    score = db.Column(db.String)

class Details(db.Model):
    __tablename__ = 'details'
    id = db.Column(db.Integer,primary_key=True)
    cve_id = db.Column(db.String(100),db.ForeignKey('cve.cve_id'))
    description = db.Column(db.String(100),nullable=False)
    severity=db.Column(db.String(100),nullable=False)
    score = db.Column(db.String)
    exploitable_score = db.Column(db.String)
    impact_score = db.Column(db.String)
    vectorString = db.Column(db.String(100))
    access_vector = db.Column(db.String(100))
    authentication = db.Column(db.String(100))
    integrity_impact = db.Column(db.String(100))
    confidentiality_impact = db.Column(db.String(100))
    access_complexity = db.Column(db.String(100))
    availability_impact = db.Column(db.String(100))

class CPEMATCH(db.Model):
    __tablename__="cpematch"
    id = db.Column(db.Integer,primary_key=True)
    cve_id = db.Column(db.String(100),nullable=False)
    vulnerable=db.Column(db.String(100))
    criteria = db.Column(db.String(100))
    matchCriteriaId=db.Column(db.String(100))

with app.app_context():
    db.create_all()

@app.route("/update")
@scheduler.task('interval', id='my_job', seconds=3600) #full batch refresh every one hour!
def update_db():

    CVE_ALL = CVE.query.all()
    for _ in CVE_ALL:
        db.session.delete(_)
        db.session.commit()

    cve_list = get_cve_list()
    for id,cve_details in enumerate(cve_list):
        id = id+1
        cve = cve_details['cve']
        cve_id = cve['id']
        last_modified = cve['lastModified'].split(":")[0][:-3]
        last_modified = datetime.strptime(last_modified, '%Y-%m-%d').date()
        published = cve['published'].split(":")[0][:-3]
        published = datetime.strptime(published, '%Y-%m-%d').date()
        source = cve['sourceIdentifier']
        status = cve['vulnStatus']
        try:
            baseScore = cve['metrics']['cvssMetricV2'][0]['cvssData']['baseScore']
        except:
            baseScore=0

        data = CVE(id = id,cve_id=cve_id,source_identifier=source,published=published,last_modified=last_modified,vuln_status=status,score=baseScore)
        db.session.add(data)
    db.session.commit()


    return redirect("/")


#A sample endpoint to extract an view the CVEs
@app.route("/get-cve-list")
def get_list():
    return jsonify({
        'details':get_cve_list()
    })

@app.route("/")
def home():
    return redirect("/cves/list")

#displays the list of CVEs
@app.route("/cves/list")
def list():

    unique_cve_id = []
    for cve_id in CVE.query.distinct(CVE.cve_id):
        unique_cve_id.append(cve_id.cve_id)
    unique_dates = []
    for dates in CVE.query.distinct(CVE.published):
        date = dates.published.year
        if date not in unique_dates:
            unique_dates.append(date)

    scores = []
    for score in CVE.query.distinct(CVE.score):
        if score.score not in scores:
            scores.append(score.score)
    
    last_modified = []
    for lm in CVE.query.distinct(CVE.last_modified):
        if lm.last_modified.year not in last_modified:
            last_modified.append(lm.last_modified.year)
        
    sc = request.args.get('score',"None")
    pb = request.args.get('published',"None")
    lm = request.args.get('last-modified',"None")
    cid = request.args.get('cve-id',"None")

    page_no = request.args.get('page-no',"1")
    items = request.args.get('items',"10")
    if sc == "None" and pb == "None" and lm == "None" and cid== "None":
        cve_list = CVE.query.paginate(per_page=int(items),page=int(page_no),error_out=True)
        tot_records = len(CVE.query.all())
    else:
        if pb == "None" and lm =="None" and cid == "None":
            cve_list = CVE.query.filter_by(score=sc).paginate(per_page=int(items),page=int(page_no),error_out=True)
            tot_records = len(CVE.query.filter_by(score=sc).all())
        elif pb == "None" and lm == "None":
            cve_list = CVE.query.filter_by(cve_id=cid).paginate(per_page=int(items),page=int(page_no),error_out=True)
            tot_records = len(CVE.query.filter_by(cve_id=cid).all())
        elif pb == "None":
            cve_list = CVE.query.order_by(CVE.last_modified.desc()).paginate(per_page=int(items),page=int(page_no),error_out=True)
            tot_records = len(CVE.query.all())
        else:
            cve_list = CVE.query.filter(extract('year',CVE.published) == pb).paginate(per_page=int(items),page=int(page_no),error_out=True)
            tot_records = len(CVE.query.filter(extract('year',CVE.published) == pb).all())



    return render_template('cve_list.html',cve_list={'cve_list':cve_list,'total_records':tot_records,'page_no':page_no,'per_page':items,'unique_cve_id':unique_cve_id,'unique_dates':unique_dates,'scores':scores,'last_modified':last_modified,'score':sc,'lm':lm,'pub':pb})

#Extracts detail about a particular CVE
@app.route("/cves/<cve_id>")
def cve_detail(cve_id):
    for i in  CPEMATCH.query.filter_by(cve_id = cve_id).all():
        db.session.delete(i)
        db.session.commit()
    

    val = Details.query.filter_by(cve_id=cve_id).first()
    if val is not None:
        db.session.delete(val)
        db.session.commit()


    add_cve_details(cve_id,db,Details,CPEMATCH)
    cpe = CPEMATCH.query.filter_by(cve_id=cve_id).all()
    cve_details = Details.query.filter_by(cve_id=cve_id).first()
    return render_template('cve_detail.html',cve_detail={'cve_detail':cve_details,'cpe':cpe})


if __name__  == "__main__":
    scheduler.init_app(app)
    scheduler.start()
    app.run(debug=True)
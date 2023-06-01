from flask import Flask,url_for,session,redirect,render_template,request,flash,send_file
from flask_mysqldb import MySQL
from flask_session import Session
from io import BytesIO
import io
import mysql.connector
import os
from otp import genotp
from cmail import sendmail
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from tokenreset import token
from token1 import token
import stripe
from flask_weasyprint import HTML, render_pdf

stripe.api_key='sk_test_51MzcVYSDVehZUuDTkwGUYe8hWu2LGN0krI8iO5QOAEqoRYXx3jgRVgkY7WzXqQmpN62oMWM59ii76NKPrRzg3Gtr005oVpiW82'
#from otp import genotp 
#from cmail import sendmail
app=Flask(__name__)
app.secret_key = '23efgbnjuytr'


app.config['SESSION_TYPE'] = 'filesystem'
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'admin'
app.config['MYSQL_DB'] = 'fooddelivery'

Session(app)
mysql = MySQL(app)
@app.route('/',methods=['GET','POST']) 
def index():
    cursor=mysql.connection.cursor()
    cursor.execute('select name from admin')
    resturants=cursor.fetchall()
    if request.method=='POST':
        rname=request.form['rnames']
        name=request.form['name']
        email=request.form['email']
        subject=request.form['subject']
        feedback=request.form['feedback']
        cursor.execute('insert into contactus values(%s,%s,%s,%s,%s)',[rname,name,email,subject,feedback])
        mysql.connection.commit()
        flash('Details submitted!')
    return render_template('home.html',resturants=resturants)
@app.route('/signin', methods = ['GET','POST'])
def register():
    if session.get('user'):
        return redirect(url_for('index'))
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password= request.form['password']
        phno= request.form['phno']
        state=request.form['state']
        address=request.form['address']
        pincode=request.form['pincode']
        cursor=mysql.connection.cursor()
        cursor.execute ('select name from user')
        data = cursor.fetchall()
        cursor.execute ('select email from user')
        edata = cursor.fetchall()
        cursor.execute ('select phnumber from user')
        pdata=cursor.fetchall()
        if (name,)in data:
            flash('user already exits')
            return render_template('usersignin.html')
        if (email,)in edata:
            flash('email already exits')                                                                                                                                                                                                                                                                                                                                                                                                                                                         
            return render_template('usersignin.html')
        if (phno,) in pdata:
            flash('Phone number already exits')                                                                                                                                                                                                                                                                                                                                                                                                                                                         
            return render_template('usersignin.html')
            
        cursor.close()
        otp = genotp()
        subject = 'thanks for registering'
        body = f'use this otp register {otp}'
        sendmail(email,subject,body)
        return render_template('otp.html',otp=otp,name=name,email=email,password=password,phno=phno,state=state,address=address,pincode=pincode)

    return render_template('usersignin.html')
@app.route('/login',methods=['GET','POST'])
def login():
    if session.get('user'):
        return redirect(url_for('index'))
    if request.method=='POST':
        name=request.form['name']
        password=request.form['password']
        cursor=mysql.connection.cursor()
        cursor.execute('select count(*) from user where name=%s and password=%s',[name,password])
        count=cursor.fetchone()[0]
        if count==0:
            flash('invalid user name or password')
            return render_template('userlogin.html')
        else:
            session['user']=name
            if not session.get(name):
                session[name]={}
            return redirect(url_for('index'))
    return render_template('userlogin.html')
@app.route('/logout')
def logout():
    if session.get('user'):
        session.pop('user')
        return redirect(url_for('index'))
    else:
        flash('you are already logged out!')
        return redirect(url_for('login'))
        #return redirect(url_for('loginp'))
@app.route('/otp/<otp>/<name>/<email>/<password>/<phno>/<state>/<address>/<pincode>',methods = ['GET','POST'])
def otp(otp,name,email,password,phno,state,address,pincode):
    if request.method == 'POST':
        uotp=request.form['otp']
        if otp == uotp:
            cursor = mysql.connection.cursor()
            cursor.execute('insert into user values(%s,%s,%s,%s,%s,%s,%s)',(name,email,password,phno,state,address,pincode))
            mysql.connection.commit()
            cursor.close()
            flash('Details Registered')#send mail to the user as successful registration
           
            return redirect(url_for('index'))
        else:
            flash('wrong otp')
            return render_template('otp.html',otp = otp,name = name,email=email,password= password,phno=phno,state=state,address=address,pincode=pincode)


@app.route('/forgetpassword',methods=['GET','POST'])
def forget():#after clicking the forget password
    if request.method=='POST':
        username=request.form['username']# store the id in the rollno
        cursor=mysql.connection.cursor()#connection to mysql
        cursor.execute('select name from user')# fetch the username data in the table students
        data=cursor.fetchall()#fetching all the rollno data and store it in the "data" variable 
        if (username,) in data:# if the given rollno of the user is present in tha database->data
            cursor.execute('select email from user where name=%s',[username])#it fetches email related to the rollno 
            data=cursor.fetchone()[0]#fetch the only one email related to the rollno 
            #print(data)
            cursor.close()
            subject=f'Reset Password for {data}'
            body=f'Reset the password using-{request.host+url_for("createpassword",token=token(username,200))}'
            sendmail(data,subject,body)
            flash('Reset link sent to your mail')
            #return redirect(url_for('login'))
        else:
            return 'Invalid username'
    return render_template('forgetpassword.html')
@app.route('/createpassword/<token>',methods=['GET','POST'])
def createpassword(token):#to create noe password and conform the password
        try:
            s=Serializer(app.config['SECRET_KEY'])
            username=s.loads(token)['user']
            if request.method=='POST':
                npass=request.form['npassword']
                cpass=request.form['cpassword']
                if npass==cpass:
                    cursor=mysql.connection.cursor()
                    cursor.execute('update user set password=%s where name=%s',[npass,username])
                    mysql.connection.commit()
                    return 'Password reset Successfull'
                    return redirect(url_for('login'))
                else:
                    return 'Password mismatch'
            return render_template('createpassword.html')
        except Exception as e:
            print(e)
            return 'Link expired try again'
#----------------------------admin login---------------------------------------
@app.route('/adminsignin', methods = ['GET','POST'])
def aregister():
    if session.get('admin'):
        return redirect(url_for('admin'))
    if request.method == 'POST':
        rid=request.form['rid']
        rname = request.form['rname']
        place= request.form['place']
        email = request.form['email']
        password= request.form['password']
        cursor=mysql.connection.cursor()
        cursor.execute ('select name from admin')
        data = cursor.fetchall()
        cursor.execute ('select email from admin')
        edata = cursor.fetchall()
        if (rid,)in data:
            flash('user already exits')
            return render_template('adminregisterpage.html')
        if (email,)in edata:
            flash('email already exits')                                                                                                                                                                                                                                                                                                                                                                                                                                                         
            return render_template('adminregisterpage.html')
        cursor.close()
        otp = genotp()
        subject = 'thanks for registering'
        body = f'use this otp register {otp}'
        sendmail(email,subject,body)
        return render_template('aotp.html',otp=otp,rid=rid,rname=rname,place=place,email=email,password=password)
    return render_template('adminregisterpage.html')
@app.route('/alogin',methods=['GET','POST'])
def alogin():
    if session.get('admin'):
        return redirect(url_for('admin'))
    if request.method=='POST':
        rid=request.form['rid']
        password=request.form['password']
        cursor=mysql.connection.cursor()
        cursor.execute('select count(*) from admin where rid=%s and password=%s',[rid,password])
        count=cursor.fetchone()[0]
        if count==0:
            flash('invalid user name or password')
            return render_template('adminlogin.html')
        else:
            session['admin']=rid
            return redirect(url_for('admin'))
    return render_template('adminlogin.html')
@app.route('/alogout')
def alogout():
    if session.get('admin'):
        session.pop('admin')
        return redirect(url_for('index'))
    else:
        flash('u are already logged out!')
        return redirect(url_for('alogin'))
        #return redirect(url_for('loginp'))
@app.route('/aotp/<otp>/<rid>/<rname>/<place>/<email>/<password>',methods = ['GET','POST'])
def aotp(otp,rid,rname,place,email,password):
    if request.method == 'POST':
        uotp=request.form['otp']
        if otp == uotp:
            cursor = mysql.connection.cursor()
            cursor.execute('insert into admin values(%s,%s,%s,%s,%s)',(rid,rname,place,email,password))
            mysql.connection.commit()
            cursor.close()
            flash('Details Registered')#send mail to the user as successful registration
            return redirect(url_for('index'))
        else:
            flash('wrong otp')
            return render_template('aotp.html',otp = otp,rid=rid,rname =rname,place=place,email=email,password= password)


@app.route('/aforgetpassword',methods=['GET','POST'])
def aforget():#after clicking the forget password
    if request.method=='POST':
        userid=request.form['rid']# store the id in the rollno
        cursor=mysql.connection.cursor()#connection to mysql
        cursor.execute('select rid from admin')# fetch the username data in the table students
        data=cursor.fetchall()#fetching all the rollno data and store it in the "data" variable 
        if (userid,) in data:# if the given rollno of the user is present in tha database->data
            cursor.execute('select email from admin where rid=%s',[userid])#it fetches email related to the rollno 
            data=cursor.fetchone()[0]#fetch the only one email related to the rollno 
            #print(data)
            cursor.close()
            subject=f'Reset Password for {data}'
            body=f'Reset the password using-{request.host+url_for("acreatepassword",token=token(userid,200))}'
            sendmail(data,subject,body)
            flash('Reset link sent to your mail')
            #return redirect(url_for('login'))
        else:
            return 'Invalid user id'
    return render_template('aforgetpassword.html')
@app.route('/acreatepassword/<token>',methods=['GET','POST'])
def acreatepassword(token):#to create noe password and conform the password
        try:
            s=Serializer(app.config['SECRET_KEY'])
            username=s.loads(token)['admin']
            if request.method=='POST':
                npass=request.form['npassword']
                cpass=request.form['cpassword']
                if npass==cpass:
                    cursor=mysql.connection.cursor()
                    cursor.execute('update admin set password=%s where rid=%s',[npass,username])
                    mysql.connection.commit()
                    return 'Password reset Successfull'
                    return redirect(url_for('login'))
                else:
                    return 'Password mismatch'
            return render_template('acreatepassword.html')
        except Exception as e:
            print(e)
            return 'Link expired try again'
#----------------------------------------------admindashboard

@app.route('/admindashboard',methods=['GET','POST'])
def admindashboard():
    if request.method=="POST":
        id1=genotp()
        name=request.form['name']
        category=request.form['category']
        price=request.form['price']
        image=request.files['image']
        cursor=mydb.cursor()
        filename=id1+'.jpg'
        cursor.execute('insert into additems(itemid,name,category,price,rid) values(%s,%s,%s,%s,%s)',[id1,name,category,price,session.get('admin')])
        mydb.commit()
        print(filename)
        path=r"C:\Users\kalyanijarugulla\OneDrive\Desktop\fd\static"
        image.save(os.path.join(path,filename))
        print('success')
        return redirect(url_for('available'))
    return render_template('admindashboard.html')

#-------------------only session resturant items view to the admin

@app.route('/available')
def available():
    if session.get('admin'):       
        cursor=mysql.connection.cursor()
        cursor.execute('select * from additems where rid=%s',[session.get('admin')])
        items=cursor.fetchall()
        return render_template('availableitems.html',items=items)
    else:
        return redirect(url_for('alogin'))
@app.route('/updateitem/<itemid>',methods=['GET','POST'])
def updateitem(itemid):
    if session.get('admin'):
        cursor=mysql.connection.cursor()
        cursor.execute('select name,category,price from additems where itemid=%s',[itemid])
        items=cursor.fetchone()
        cursor.close()
        if request.method=='POST':
            name=request.form['name']
            category=request.form['category']
            price=request.form['price']
            cursor=mysql.connection.cursor()
            cursor.execute('update additems set name=%s,category=%s,price=%s where itemid=%s',[name,category,price,itemid])
            mysql.connection.commit()
            cursor.close()
            flash('item updated successfully')
            return redirect(url_for('available'))
        return render_template('updateitems.html',items=items)
    else:
        return redirect(url_for('alogin'))
@app.route('/deleteitem/<itemid>')
def deleteitem(itemid):
    cursor=mysql.connection.cursor()
    cursor.execute('delete from additems where itemid=%s',[itemid])
    mysql.connection.commit()
    cursor.close()
    path=r"C:\Users\kalyanijarugulla\OneDrive\Desktop\fd\static"
    filename=f"{itemid}.jpg"
    os.remove(os.path.join(path,filename))
    flash('item deleted successfully')
    return redirect(url_for('available'))
@app.route('/admin')
def admin():
    if session.get('admin'):
        return render_template('adminpage.html')
    else:
        return redirect(url_for('alogin'))
#-----------------all resturant items view to the user-----------------
@app.route('/itemspage')
def itemspage():
    cursor=mysql.connection.cursor()
    cursor.execute('select * from additems')
    items=cursor.fetchall()
    #print(name)
    #print(items)
    return render_template('itemspage.html',items=items)
@app.route('/homepage/<category>')
def homepage(category):
    cursor=mysql.connection.cursor()
    cursor.execute('select * from additems where category=%s',[category])
    items=cursor.fetchall()
    return render_template('itemspage.html',items=items)
@app.route('/returantshome/<name>')
def resturantshome(name):
    cursor=mysql.connection.cursor()
    cursor.execute('select rid from admin where name=%s',[name])
    rid=cursor.fetchone()[0]
    cursor.execute('select * from additems where rid=%s',[rid])
    ritems=cursor.fetchall()
    cursor.execute('select name from admin')
    resturants=cursor.fetchall()

    return render_template('resturantshome.html',ritems=ritems,resturants=resturants)
#--------------------------------cart card---------------------------------------------------
@app.route('/items',methods=['GET','POST'])
def items():
    return render_template('itemsPage.html')
@app.route('/cart/<itemid>/<name>/<price>',methods=['GET','POST'])
def cart(itemid,name,price):
    if session.get('user'):
        if request.method=='POST':
            qty=int(request.form['qty'])
            if itemid not in session.get(session.get('user')):
                session[session.get('user')][itemid]=[name,qty,price]
                session.modified=True
                #print(session['session.get('user''])
                flash(f'{name} added to cart')
                return redirect(url_for('viewcart'))
            session[session.get('user')][itemid][1]+=qty
            session.modified=True
            flash('Item already in cart quantity increased to +1')
        return redirect(url_for('viewcart'))
    return redirect(url_for('login'))
@app.route('/viewcart')
def viewcart():
    if not session.get('user'):
        return redirect(url_for('login'))
   
    items=session.get(session.get('user')) if session.get(session.get('user')) else 'empty'
    if items=='empty':
        return 'no products in cart'
    return render_template('cart.html',items=items)
@app.route('/remcart/<item>')
def rem(item):
    if session.get('user'):
        session[session.get('user')].pop(item)
        return redirect(url_for('viewcart'))
    return redirect(url_for('login'))
@app.route('/pay/<itemid>/<name>/<int:price>',methods=['POST'])
def pay(itemid,price,name):
    if session.get('user'):
        q=int(request.form['qty'])
        username=session.get('user')
        total=price*q
        checkout_session=stripe.checkout.Session.create(
            success_url=url_for('success',itemid=itemid,name=name,q=q,total=total,_external=True),
            line_items=[
                {
                    'price_data': {
                        'product_data': {
                            'name': name,
                        },
                        'unit_amount': price*100,
                        'currency': 'inr',
                    },
                    'quantity': q,
                },
                ],
            mode="payment",)
        return redirect(checkout_session.url)
    else:
        return redirect(url_for('login'))
@app.route('/success/<itemid>/<name>/<q>/<total>')
def success(itemid,name,q,total):
    if session.get('user'):
        cursor=mysql.connection.cursor()
        cursor.execute('SELECT rid from additems where itemid=%s',[itemid])
        rid=cursor.fetchone()[0]
        cursor.execute('insert into orders(itemid,name,qty,total_price,user,rid) values(%s,%s,%s,%s,%s,%s)',[itemid,name,q,total,session.get('user'),rid])
        mysql.connection.commit()
        return redirect(url_for('orders'))
    return redirect(url_for('login'))
@app.route('/orders')
def orders():
    if session.get('user'):
        cursor=mysql.connection.cursor()
        cursor.execute('select * from orders where user=%s',(session['user'],))
       
        orders=cursor.fetchall()
        
        return render_template('orders.html',orders=orders)
@app.route('/search',methods=['GET','POST'])
def search():
    if request.method=="POST":
        name=request.form['search']
        cursor=mysql.connection.cursor()
        cursor.execute('select * from additems where name=%s',[name])
        data=cursor.fetchall()
        return render_template('itemspage.html',items=data)
@app.route('/readcontact')
def readcontact():
    if session.get('admin'):
        cursor=mysql.connection.cursor()
        cursor.execute('select name from admin where rid=%s',[session.get('admin')])
        r_data=cursor.fetchone()
        cursor.execute('select * from contactus where resturant_name=%s',[r_data])
        
        details=cursor.fetchall()
        return render_template('readcontact.html',details=details) 
    else:
        return redirect(url_for('alogin')) 
@app.route('/buyallitems')
def buyallitems():
    if session.get('user'):
        line_items=[]
        data=session.get(session.get('user'))

        print(data.keys())
        print(data.items())
        
        for i in data:
            k={'price_data':{'product_data':{'name': data[i][0]},'unit_amount': int(data[i][2])*100,'currency': 'inr'},'quantity':data[i][1]}
            line_items.append(k)
        #print(line_items)
        checkout_session=stripe.checkout.Session.create(
                success_url=url_for('allcheckout',_external=True),
                line_items=line_items,mode="payment")
        return redirect(checkout_session.url)
    else:
        return redirect(url_for('login'))

@app.route('/allcheckout')
def allcheckout():
    if session.get('user'):
        cart=session.get(session.get('user'))
        lst=[]
        for i in cart:
            cursor=mysql.connection.cursor()
            cursor.execute('SELECT rid from additems where itemid=%s',[i])
            rid=cursor.fetchone()[0]
            lst.append((i,cart[i][0],cart[i][1],cart[i][1]*int(cart[i][2]),session.get('user'),rid))
            cursor.close()
        session[session.get('user')]={}
        session.modified=True
        cursor=mysql.connection.cursor()
        cursor.executemany('insert into orders(itemid,name,qty,total_price,user,rid) values(%s,%s,%s,%s,%s,%s)',lst)
        mysql.connection.commit()

        return redirect(url_for('orders'))
    else:
        return redirect(url_for('login'))
@app.route('/seeorders')
def seeorders():
    if session.get('admin'):
        cursor=mysql.connection.cursor()
        cursor.execute('select * from orders where rid=%s',(session['admin'],))
        orders=cursor.fetchall()
        return render_template('seeorders.html',orders=orders)
@app.route('/billdetails/<ordid>.pdf')
def invoice(ordid):
    # Make a PDF straight from HTML in a string.
    cursor=mysql.connection.cursor()
    cursor.execute('select * from orders where ordid=%s',[ordid])
    orders=cursor.fetchone()
    username=orders[5]
    rid=orders[6]
    oname=orders[2]
    qty=orders[3]
    cost=orders[4]
    cursor.execute('select name,place from admin where rid=%s',[rid])
    admin=cursor.fetchone()
    name=admin[0]
    rplace=admin[1]
    cursor.execute('select name,phnumber,state,address,pincode from user where name=%s',[username])
    data=cursor.fetchone()
    uname=data[0]
    uaddress=data[3]
    uphnumber=data[1]
    html = render_template('billdetails.html', name=name,place=rplace,uname=uname,uaddress=uaddress,uphnumber=uphnumber,oname=oname,qty=qty,cost=cost)
    return render_pdf(HTML(string=html))  
app.run(debug=True, use_reloader=True)


    
    
       
        

#!/usr/bin/env python3
'''Populate database with random placeholder items'''
import random

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import app
from app.models import Base, User, Item, Category

# Connect to database
engine = create_engine(app.config['SQLALCHEMY_DATABASE_URI'])
Base.metadata.create_all(engine)
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()

# Update this email address with your own
email_address = 'user@example.com'

lorem_ipsums = ['Lorem ipsum dolor sit amet, consectetur adipiscing elit. '
                'Integer risus urna, imperdiet eu quam ut, posuere imperdiet '
                'ante. Nunc vitae ante vitae arcu bibendum commodo. Vivamus '
                'consequat ornare ipsum, sed fringilla dolor interdum in. '
                'Nullam dapibus, ex id mollis lobortis, nunc turpis '
                'sollicitudin quam, in varius felis dolor quis lectus. Nulla '
                'suscipit arcu scelerisque cursus ultricies. Aliquam erat '
                'volutpat. Class aptent taciti sociosqu ad litora torquent '
                'per conubia nostra, per inceptos himenaeos. Vivamus eget '
                'lacus convallis, feugiat sem nec, semper massa. Fusce '
                'fermentum tortor a quam rhoncus sagittis. Aenean viverra '
                'pretium arcu, a porta sapien feugiat in. Nunc sem augue, '
                'tristique at finibus sed, laoreet sed ligula. Vivamus at '
                'gravida nulla.',
                'Lorem ipsum dolor sit amet, consectetur adipiscing elit. '
                'Duis eget porta eros. Ut orci est, vehicula non lorem '
                'vestibulum, feugiat tincidunt leo. Vestibulum ullamcorper '
                'eget orci id commodo. Etiam venenatis eros at mattis tempor. '
                'Donec lacinia vel magna vel rutrum. Curabitur varius diam '
                'vel ante tempor faucibus. Morbi tempus nulla massa, sit amet '
                'ultricies nulla tristique non. Vivamus mauris lectus, mollis '
                'a quam a, tincidunt sollicitudin elit. Vestibulum '
                'pellentesque maximus scelerisque. Proin porta non justo id '
                'sollicitudin. Etiam egestas ante leo, non finibus sapien '
                'mattis sit amet. Pellentesque velit massa, posuere in nunc '
                'a, commodo dictum purus. Suspendisse vulputate diam id '
                'finibus faucibus. Vivamus vel odio id tortor molestie '
                'laoreet. In ornare, nulla ac accumsan maximus, lacus metus '
                'dapibus erat, interdum aliquam elit ex ut purus.',
                'Lorem ipsum dolor sit amet, consectetur adipiscing elit. '
                'Cras varius in dui sit amet aliquam. Quisque fringilla velit '
                'mauris, eget viverra est bibendum vel. Donec porttitor id '
                'tellus at laoreet. Aenean quis tellus id erat aliquet '
                'consequat. Sed fermentum enim sed nulla vulputate, non '
                'consectetur metus consequat. Morbi semper aliquam molestie. '
                'Vestibulum ante ipsum primis in faucibus orci luctus et '
                'ultrices posuere cubilia Curae; Fusce vitae dapibus velit. '
                'Mauris vitae dictum risus. Pellentesque pharetra massa in '
                'vulputate elementum. Donec sit amet orci suscipit, iaculis '
                'leo ullamcorper, efficitur neque. Pellentesque euismod, diam '
                'at tempor porta, tortor tortor dapibus nunc, vitae laoreet '
                'nulla est non mi.',
                'Lorem ipsum dolor sit amet, consectetur adipiscing elit. '
                'Donec ornare viverra neque quis euismod. Quisque at lorem '
                'quis sapien tempor mattis. Fusce ornare fringilla ex, vel '
                'faucibus lectus feugiat in. Nam tincidunt tempus enim, eu '
                'consectetur nibh maximus at. Fusce ac urna eget sapien porta '
                'consequat vitae lobortis mi. Phasellus aliquam sapien sem, '
                'ac feugiat ipsum placerat sed. Phasellus convallis gravida '
                'dictum. Suspendisse vitae erat sodales, finibus metus quis, '
                'finibus magna. Interdum et malesuada fames ac ante ipsum '
                'primis in faucibus. Phasellus dignissim purus nisl, sit amet '
                'egestas tortor sollicitudin sed. Vivamus sit amet sapien '
                'quis arcu tristique interdum et id lorem. Pellentesque erat '
                'ante, euismod vel hendrerit at, malesuada sit amet sapien. '
                'Pellentesque tempus efficitur libero a tempus. Donec tellus '
                'purus, fringilla sit amet efficitur sed, consequat a erat. '
                'Fusce et dolor lorem. Aenean pretium lacus rhoncus, maximus '
                'ante in, sodales metus.',
                'Lorem ipsum dolor sit amet, consectetur adipiscing elit. '
                'Praesent et volutpat dolor. Integer tellus ante, euismod sit '
                'amet risus a, consectetur fermentum odio. Fusce vulputate, '
                'dui eleifend elementum dictum, justo mauris semper mi, '
                'rutrum commodo metus magna eu nunc. Pellentesque habitant '
                'morbi tristique senectus et netus et malesuada fames ac '
                'turpis egestas. Quisque nec ipsum scelerisque, accumsan '
                'felis at, luctus purus. Integer nulla erat, gravida at est '
                'vel, imperdiet cursus dui. Nulla mollis arcu eget felis '
                'vehicula tempor. Fusce sit amet mollis arcu, sed porttitor '
                'est. Mauris vel justo in nulla egestas feugiat sit amet '
                'cursus felis. Nulla gravida tortor a urna ullamcorper, id '
                'feugiat massa egestas. Maecenas quis dolor est. Nulla in '
                'ante sed dolor mattis pulvinar quis et ante. Quisque '
                'hendrerit, tortor et aliquet porta, velit lacus lobortis '
                'justo, at pellentesque quam metus ut urna. Nunc eget viverra '
                'lectus, et vulputate leo. Integer orci felis, malesuada '
                'vitae vehicula sit amet, condimentum ac mauris.',
                'Lorem ipsum dolor sit amet, consectetur adipiscing elit. '
                'Fusce auctor eros purus, nec ultrices ante congue at. Proin '
                'aliquam lorem semper, fringilla dolor ac, vulputate eros. '
                'Quisque dignissim bibendum libero at congue. Suspendisse '
                'potenti. Aenean pellentesque, elit eu posuere molestie, nibh '
                'nisi aliquam mi, et vehicula dui justo at urna. Vivamus ac '
                'odio lectus. Curabitur sit amet velit vel nisl rutrum '
                'malesuada.',
                'Lorem ipsum dolor sit amet, consectetur adipiscing elit. '
                'Proin nunc libero, condimentum eget efficitur eget, aliquam '
                'at nunc. Quisque vitae pretium arcu, vel egestas augue. '
                'Class aptent taciti sociosqu ad litora torquent per conubia '
                'nostra, per inceptos himenaeos. Vestibulum ante ipsum primis '
                'in faucibus orci luctus et ultrices posuere cubilia Curae; '
                'Ut facilisis nulla eget metus feugiat maximus. Nam vel massa '
                'sodales, dignissim lectus sit amet, congue ante. Nulla eget '
                'tortor risus. Sed venenatis lectus sit amet purus fringilla, '
                'ac lobortis ipsum pharetra. Ut non erat in ipsum malesuada '
                'bibendum sit amet a mi. Fusce hendrerit porta feugiat. Etiam '
                'sagittis sodales tortor, non placerat massa vulputate at. '
                'Integer vel neque pharetra, dictum nisi at, convallis '
                'turpis. Maecenas feugiat auctor sem, vel interdum orci '
                'pulvinar non. Integer pulvinar elit quis porta ullamcorper. '
                'Quisque eget elit arcu.',
                'Lorem ipsum dolor sit amet, consectetur adipiscing elit. '
                'Proin nunc libero, condimentum eget efficitur eget, aliquam '
                'at nunc. Quisque vitae pretium arcu, vel egestas augue. '
                'Class aptent taciti sociosqu ad litora torquent per conubia '
                'nostra, per inceptos himenaeos. Vestibulum ante ipsum primis '
                'in faucibus orci luctus et ultrices posuere cubilia Curae; '
                'Ut facilisis nulla eget metus feugiat maximus. Nam vel massa '
                'sodales, dignissim lectus sit amet, congue ante. Nulla eget '
                'tortor risus. Sed venenatis lectus sit amet purus fringilla, '
                'ac lobortis ipsum pharetra. Ut non erat in ipsum malesuada '
                'bibendum sit amet a mi. Fusce hendrerit porta feugiat. Etiam '
                'sagittis sodales tortor, non placerat massa vulputate at. '
                'Integer vel neque pharetra, dictum nisi at, convallis '
                'turpis. Maecenas feugiat auctor sem, vel interdum orci '
                'pulvinar non. Integer pulvinar elit quis porta ullamcorper. '
                'Quisque eget elit arcu.',
                'Lorem ipsum dolor sit amet, consectetur adipiscing elit. '
                'Donec commodo lacus sapien, sit amet elementum enim finibus '
                'in. Aliquam ultrices massa vel nulla blandit blandit. Nunc '
                'vel ligula sed elit tristique lacinia. Donec lobortis lacus '
                'vel elementum posuere. Mauris convallis, sem semper gravida '
                'aliquam, ligula erat venenatis libero, sit amet pretium '
                'neque enim eget ipsum. Vivamus ultricies rutrum erat. Proin '
                'vel ultrices velit. Nullam maximus id orci sed sagittis. '
                'Aliquam a molestie ipsum. Nulla a dolor dapibus, elementum '
                'magna et, egestas arcu.']

lorem_ipsum_words = ['Lorem', 'Ullamcorper', 'Aliquam', 'Dapibus', 'Hendrerit',
                     'Elementum', 'Dolor', 'Magna', 'Fringilla', 'Sociosqu',
                     'Facilisis', 'Blandit', 'Phasellus', 'Aenean', 'Proin',
                     'Vestibulum', 'Maecenas', 'Pellentesque', 'Donec',
                     'Curabitur', 'Etiam', 'Nam', 'Class', 'Quisque', 'Fusce',
                     'Morbi', 'Vivamus', 'Nulla', 'Integer', 'Curae',
                     'Suspendisse']

placeholder_image_urls = ['http://lorempixel.com/400/200',
                          'https://placebear.com/400/200',
                          'http://fillmurray.com/400/200',
                          'http://www.placecage.com/400/200',
                          'http://www.placecage.com/c/400/200']

# Add categories to database
for categorie_name in lorem_ipsum_words:
    category = Category(name=categorie_name)
    session.add(category)
    session.commit()

# Add an user to database
user = User(email=email_address)
session.add(user)
session.commit()

categories = session.query(Category).all()
users = session.query(User).all()

# Populate database with items
for i in range(1, 100):
    item = Item(name=random.choice(lorem_ipsum_words),
                description=random.choice(lorem_ipsums),
                category_id=random.choice(categories).id,
                user_id=random.choice(users).id,
                image_url=random.choice(placeholder_image_urls))
    session.add(item)
    try:
        session.commit()
    except:
        session.rollback()

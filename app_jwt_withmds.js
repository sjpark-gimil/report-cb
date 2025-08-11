const express = require('express');
const session = require('express-session');
const fs = require('fs');
const path = require('path');
const { Low, JSONFile } = require('lowdb');
const FileSync = require('lowdb/adapters/FileSync');
const { createProxyMiddleware } = require('http-proxy-middleware');
const axios = require('axios');
const puppeteer = require('puppeteer');
const adapter = new FileSync('db.json');
const db = require('lowdb')(adapter);
const requireAuth = require('./auth');
const reviewModeration = {
  rateLimit: new Map(),
  inappropriateWords: [
    'spam', 'advertisement', 'promote', 'sell', 'buy', 'money', 'profit',
    'scam', 'fake', 'fraud', 'hack', 'crack', 'illegal', 'porn', 'sex',
    'drug', 'violence', 'hate', 'racist', 'discriminate'
  ],

  checkRateLimit: (ip) => {
    const now = Date.now();
    const hourAgo = now - (60 * 60 * 1000);
    
    if (!reviewModeration.rateLimit.has(ip)) {
      reviewModeration.rateLimit.set(ip, []);
    }
    
    const submissions = reviewModeration.rateLimit.get(ip);
    const recentSubmissions = submissions.filter(time => time > hourAgo);
    
    if (recentSubmissions.length >= 3) {
      return false;
    }
    
    recentSubmissions.push(now);
    reviewModeration.rateLimit.set(ip, recentSubmissions);
    return true;
  },

  validateReview: (username, comment, rating, lang = 'en') => {
    const errors = [];
    const t = languages[lang] || languages.en;
  
    if (!username || username.trim().length < 2) {
      errors.push(t.reviews.validation.username_min_length);
    }
    if (username && username.length > 50) {
      errors.push(t.reviews.validation.username_max_length);
    }

    if (!comment || comment.trim().length < 10) {
      errors.push(t.reviews.validation.comment_min_length);
    }
    if (comment && comment.length > 500) {
      errors.push(t.reviews.validation.comment_max_length);
    }

    if (!rating || isNaN(rating) || rating < 1 || rating > 5) {
      errors.push(t.reviews.validation.rating_invalid);
    }

    const lowerComment = comment.toLowerCase();
    const lowerUsername = username.toLowerCase();
    
    for (const word of reviewModeration.inappropriateWords) {
      if (lowerComment.includes(word) || lowerUsername.includes(word)) {
        errors.push(t.reviews.validation.inappropriate_content);
        break;
      }
    }

    if (comment.includes('http://') || comment.includes('https://')) {
      errors.push(t.reviews.validation.links_not_allowed);
    }
    
    if (comment.includes('@') && comment.includes('.com')) {
      errors.push(t.reviews.validation.email_not_allowed);
    }
    
    return {
      isValid: errors.length === 0,
      errors,
      sanitizedData: {
        username: username ? username.trim().substring(0, 50) : '',
        comment: comment ? comment.trim().substring(0, 500) : '',
        rating: parseInt(rating) || 0
      }
    };
  }
};

setInterval(() => {
  const now = Date.now();
  const hourAgo = now - (60 * 60 * 1000);
  
  for (const [ip, submissions] of reviewModeration.rateLimit.entries()) {
    const recentSubmissions = submissions.filter(time => time > hourAgo);
    if (recentSubmissions.length === 0) {
      reviewModeration.rateLimit.delete(ip);
    } else {
      reviewModeration.rateLimit.set(ip, recentSubmissions);
    }
  }
}, 60 * 60 * 1000);

const loadLanguage = (lang) => {
  try {
    const langPath = path.join(__dirname, 'locales', `${lang}.json`);
    return JSON.parse(fs.readFileSync(langPath, 'utf8'));
  } catch (error) {
    console.warn(`Language file for ${lang} not found, falling back to English`);
    return JSON.parse(fs.readFileSync(path.join(__dirname, 'locales', 'en.json'), 'utf8'));
  }
};

const languages = { en: loadLanguage('en'), ko: loadLanguage('ko')};

const app = express(); 
const PORT = 3000;

app.use(session({
  secret: 'beamerxsecret',
  resave: false,
  saveUninitialized: true
}));

app.set('view engine', 'ejs');
app.use(express.static('public'));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use((req, res, next) => {
  const lang = req.query.lang || req.session.lang || 'en';
  req.session.lang = lang;
  res.locals.lang = lang;
  res.locals.t = languages[lang] || languages.en;
  res.locals.currentLang = lang;
  res.locals.availableLanguages = { en: 'English', ko: '한국어' };
  next();
});


async function main() {
  await db.read();
  db.data ||= { apps: [] };

const platform = {
  id: 'codebeamer',
  name: 'Codebeamer',
  url: 'http://codebeamer.mdsit.co.kr:3008',
  description: 'Main Codebeamer platform for application lifecycle management',
  isPlatform: true
};

const apps = [
  { id: 'gantt', name: 'Gantt', url: 'http://codebeamer.mdsit.co.kr:3002', description: 'MDS Gantt for Codebeamer' },
  // { id: 'neoatf', name: 'NEO-ATF', url: 'http://codebeamer.mdsit.co.kr:3001', description: 'Helix QAC, CodeSonar and VectorCAST trigger by one click' },
  // { id: 'report', name: 'Connector for NEO-ATF', url: 'http://codebeamer.mdsit.co.kr:3003', description: 'Upload and view test reports' },
  { id: 'medini', name: 'Medini Analyze Plugin', url: 'http://codebeamer.mdsit.co.kr:3004', description: 'Safety analysis plugin' },
  { id: 'dashboard', name: 'Glance Viewer', url: 'http://codebeamer.mdsit.co.kr:3006', description: 'Visual dashboards for Codebeamer' },
  { id: 'vectorcast', name: 'VectorCAST Report Hub', url: 'http://codebeamer.mdsit.co.kr:3007', description: 'Centralized report hub for VectorCAST' },
];


app.get('/apps/:id', async (req, res) => {
    await db.read();
    const appData = apps.find(a => a.id === req.params.id);
    if (appData) {
      let dbApp = db.data.apps.find(a => a.id === req.params.id);
      if (!dbApp) {
        dbApp = { id: req.params.id, visitCount: 0, reviews: [], visitIPs: [] };
        db.data.apps.push(dbApp);
      }
      
      const clientIP = req.ip || req.connection.remoteAddress;
      
      dbApp.visitCount = (dbApp.visitCount || 0) + 1;
      dbApp.visitIPs = dbApp.visitIPs || [];
      
      const visitRecord = {
        ip: clientIP,
        timestamp: new Date().toISOString(),
        userAgent: req.get('User-Agent') || 'Unknown'
      };
      
      dbApp.visitIPs.push(visitRecord);
      await db.write();
     
      const lang = req.query.lang || 'en';
      const t = languages[lang] || languages['en'];
      const mergedAppData = { ...appData, ...dbApp };
      res.render('app_detail', { 
        appData: mergedAppData, 
        t, 
        req 
      });
    } else {
      res.status(404).send('App not found');
    }
  });
  
  app.post('/apps/:id/review', async (req, res) => {
    const { username, comment, rating } = req.body;
    const clientIP = req.ip || req.connection.remoteAddress;
    const lang = req.query.lang || req.session.lang || 'en';
    const t = languages[lang] || languages.en;

    if (!reviewModeration.checkRateLimit(clientIP)) {
      return res.status(429).render('error', {
        message: 'Too many review submissions. Please wait before submitting another review.',
        backUrl: `/apps/${req.params.id}`
      });
    }

    const validation = reviewModeration.validateReview(username, comment, rating, lang);
    if (!validation.isValid) {
      return res.status(400).render('error', {
        message: `${t.reviews.validation.validation_failed}: ${validation.errors.join(', ')}`,
        backUrl: `/apps/${req.params.id}`
      });
    }
    
    await db.read();

    const hardcodedApp = apps.find(a => a.id === req.params.id);
    if (hardcodedApp) {
      let dbApp = db.data.apps.find(a => a.id === req.params.id);
      if (!dbApp) {
        dbApp = { id: req.params.id, visitCount: 0, reviews: [], pendingReviews: [] };
        db.data.apps.push(dbApp);
      }

      dbApp.reviews = dbApp.reviews || [];
      dbApp.pendingReviews = dbApp.pendingReviews || [];

      const review = {
        id: Date.now().toString() + Math.random().toString(36).substr(2, 9),
        username: validation.sanitizedData.username,
        comment: validation.sanitizedData.comment,
        rating: validation.sanitizedData.rating,
        date: new Date().toISOString(),
        status: 'pending', // pending, approved, rejected
        ip: clientIP
      };

      dbApp.pendingReviews.push(review);
      await db.write();
      
      res.redirect(`/apps/${req.params.id}?message=리뷰가 성공적으로 제출되었습니다. 관리자가 검토 후 승인됩니다.`);
    } else {
      res.status(404).send('App not found');
    }
  });
  

app.get('/faq', (req, res) => {
  res.render('faq', { apps });
});

// Chat routes
app.get('/api/chat/messages', async (req, res) => {
  await db.read();
  const messages = db.data.chatMessages || [];
  res.json(messages);
});

app.post('/api/chat/send', async (req, res) => {
  const { message, userId } = req.body;
  await db.read();
  
  if (!db.data.chatMessages) {
    db.data.chatMessages = [];
  }
  
  const chatMessage = {
    id: Date.now().toString() + Math.random().toString(36).substr(2, 9),
    message: message,
    userId: userId || 'anonymous',
    sender: 'user',
    timestamp: new Date().toISOString(),
    status: 'unread'
  };
  
  db.data.chatMessages.push(chatMessage);
  await db.write();
  
  res.json({ success: true, message: chatMessage });
});

app.post('/api/chat/admin/reply', requireAuth, async (req, res) => {
  const { messageId, reply } = req.body;
  await db.read();
  
  const originalMessage = db.data.chatMessages.find(m => m.id === messageId);
  if (!originalMessage) {
    return res.status(404).json({ error: 'Message not found' });
  }
  
  originalMessage.status = 'replied';
  
  const adminReply = {
    id: Date.now().toString() + Math.random().toString(36).substr(2, 9),
    message: reply,
    userId: originalMessage.userId,
    sender: 'admin',
    timestamp: new Date().toISOString(),
    replyTo: messageId
  };
  
  db.data.chatMessages.push(adminReply);
  await db.write();
  
  res.json({ success: true, reply: adminReply });
});

app.get('/admin/chat', requireAuth, async (req, res) => {
  await db.read();
  const messages = db.data.chatMessages || [];
  res.render('admin_chat', { messages });
});

app.get('/contact', (req, res) => {
  res.render('contact', { req });
});

app.post('/contact', async (req, res) => {
  const { name, email, subject, message } = req.body;
  const clientIP = req.ip || req.connection.remoteAddress;

  if (!name || !email || !subject || !message) {
    return res.status(400).render('error', {
      message: 'All fields are required',
      backUrl: '/contact'
    });
  }

  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!emailRegex.test(email)) {
    return res.status(400).render('error', {
      message: 'Please enter a valid email address',
      backUrl: '/contact'
    });
  }
  
  await db.read();

  if (!db.data.messages) {
    db.data.messages = [];
  }

  const contactMessage = {
    id: Date.now().toString() + Math.random().toString(36).substr(2, 9),
    name: name.trim(),
    email: email.trim(),
    subject: subject.trim(),
    message: message.trim(),
    date: new Date().toISOString(),
    status: 'unread',
    ip: clientIP
  };

  db.data.messages.push(contactMessage);
  await db.write();
  
  res.redirect('/contact?message=감사합니다! 관리자가 확인 후 연락 드리겠습니다.');
});

app.get('/admin/login', (req, res) => {
    res.render('admin_login');
  });
  
  app.post('/admin/login', (req, res) => {
    const { username, password } = req.body;
    if (username === 'admin' && password === '1234') {
      req.session.user = 'admin';
      res.redirect('/admin');
    } else {
      res.send('Invalid credentials');
    }
  });

  app.get('/admin', requireAuth, (req, res) => {
    res.render('admin_dashboard');
  });

  app.get('/admin/apps', requireAuth, async (req, res) => {
    await db.read();
    
    const allApps = [];
    
    // Add hardcoded apps
    apps.forEach(app => {
      const dbApp = db.data.apps.find(dbApp => dbApp.id === app.id);
      const mergedApp = {
        ...app,
        visitCount: dbApp ? dbApp.visitCount : 0,
        reviews: dbApp ? dbApp.reviews : [],
        pendingReviews: dbApp ? dbApp.pendingReviews : [],
        visitIPs: dbApp ? dbApp.visitIPs : []
      };
      allApps.push(mergedApp);
    });
    
    // Add any additional apps from database that aren't in hardcoded list
    db.data.apps.forEach(dbApp => {
      if (!apps.find(app => app.id === dbApp.id)) {
        allApps.push(dbApp);
      }
    });
    
    res.render('admin_apps', { apps: allApps });
  });
  
  app.get('/admin/apps/add', requireAuth, (req, res) => {
    res.render('admin_apps_add');
  });
  
  app.post('/admin/apps/add', requireAuth, async (req, res) => {
    const { id, name, url, description } = req.body;
    db.data.apps.push({ id, name, url, description });
    await db.write();
    res.redirect('/admin/apps');
  });
  
  app.get('/admin/apps/edit/:id', requireAuth, async (req, res) => {
    await db.read();
    const appData = db.data.apps.find(a => a.id === req.params.id);
    res.render('admin_apps_edit', { appData });
  });
  
  app.post('/admin/apps/edit/:id', requireAuth, async (req, res) => {
    const { name, url, description } = req.body;
    const appData = db.data.apps.find(a => a.id === req.params.id);
    appData.name = name;
    appData.url = url;
    appData.description = description;
    await db.write();
    res.redirect('/admin/apps');
  });
 
  app.get('/admin/reviews', requireAuth, async (req, res) => {
    await db.read();
    const appsWithPendingReviews = db.data.apps.filter(app => 
      (app.pendingReviews && app.pendingReviews.length > 0) || 
      (app.reviews && app.reviews.length > 0)
    );
    res.render('admin_reviews', { apps: appsWithPendingReviews });
  });
  
  app.get('/admin/reviews/:appId', requireAuth, async (req, res) => {
    await db.read();
    const appData = db.data.apps.find(a => a.id === req.params.appId);
    if (!appData) {
      return res.status(404).send('App not found');
    }
    res.render('admin_reviews_detail', { appData, req });
  });
  
  app.post('/admin/reviews/:appId/:reviewId/approve', requireAuth, async (req, res) => {
    await db.read();
    const appData = db.data.apps.find(a => a.id === req.params.appId);
    if (!appData) {
      return res.status(404).send('App not found');
    }
    
    const reviewIndex = appData.pendingReviews.findIndex(r => r.id === req.params.reviewId);
    if (reviewIndex === -1) {
      return res.status(404).send('Review not found');
    }
    
    const review = appData.pendingReviews[reviewIndex];
    review.status = 'approved';
    review.approvedDate = new Date().toISOString();
    
    appData.pendingReviews.splice(reviewIndex, 1);
    appData.reviews = appData.reviews || [];
    appData.reviews.push(review);
    
    await db.write();
    res.redirect(`/admin/reviews/${req.params.appId}?message=Review approved successfully`);
  });
  
  app.post('/admin/reviews/:appId/:reviewId/reject', requireAuth, async (req, res) => {
    await db.read();
    const appData = db.data.apps.find(a => a.id === req.params.appId);
    if (!appData) {
      return res.status(404).send('App not found');
    }
    
    const reviewIndex = appData.pendingReviews.findIndex(r => r.id === req.params.reviewId);
    if (reviewIndex === -1) {
      return res.status(404).send('Review not found');
    }
    
    const review = appData.pendingReviews[reviewIndex];
    review.status = 'rejected';
    review.rejectedDate = new Date().toISOString();
 
    appData.pendingReviews.splice(reviewIndex, 1);
    
    await db.write();
    res.redirect(`/admin/reviews/${req.params.appId}?message=Review rejected successfully`);
  });

  app.get('/admin/messages', requireAuth, async (req, res) => {
    await db.read();
    const messages = db.data.messages || [];
    res.render('admin_messages', { messages, req });
  });
  
  app.post('/admin/messages/:messageId/read', requireAuth, async (req, res) => {
    await db.read();
    const message = db.data.messages.find(m => m.id === req.params.messageId);
    if (!message) {
      return res.status(404).send('Message not found');
    }
    
    message.status = 'read';
    message.readDate = new Date().toISOString();
    await db.write();
    
    res.redirect('/admin/messages?message=Message marked as read');
  });
  
  app.post('/admin/messages/:messageId/replied', requireAuth, async (req, res) => {
    await db.read();
    const message = db.data.messages.find(m => m.id === req.params.messageId);
    if (!message) {
      return res.status(404).send('Message not found');
    }
    
    message.status = 'replied';
    message.repliedDate = new Date().toISOString();
    await db.write();
    
    res.redirect('/admin/messages?message=Message marked as replied');
  });
  
  app.post('/admin/messages/:messageId/delete', requireAuth, async (req, res) => {
    await db.read();
    const messageIndex = db.data.messages.findIndex(m => m.id === req.params.messageId);
    if (messageIndex === -1) {
      return res.status(404).send('Message not found');
    }
    
    db.data.messages.splice(messageIndex, 1);
    await db.write();
    
    res.redirect('/admin/messages?message=Message deleted successfully');
  });
  
  app.post('/admin/apps/delete/:id', requireAuth, async (req, res) => {
    db.data.apps = db.data.apps.filter(a => a.id !== req.params.id);
    await db.write();
    res.redirect('/admin/apps');
  });


  
   const jwt = require('jsonwebtoken');
   const crypto = require('crypto');
   const CB_JWT_SECRET = "CB-ENCRYPTED-D4-6E-6C-91-E4-56-4E-40-77-E2-9A-7A-E5-B7-5E-92-73-44-29-56-74-4C-B9-ED-86-A8-8-76-2-68-6E-A5-44-8E-1F-AD-DD-85-EF-E7-8E-B1-F9-8D-C1-46-D3-46-A6-7D-E4-B5-C8-2-4A-B9-18-BB-BA-2-92-AA-AE-3F-4E-DD-29-18-4B-11-85-C9-E7-0-69-58-B-A7-91-F4-CB-F3-10-43-9E-D9-E-B9-D0-0-1C-1F-9A-EF-C7-EB-0-6F-2E-37-3D-A1-7A-56-DB-6E-CB-3B-6D-C6-1C-3E-F1-A8-F8-BD-4A-BE-79-8-EE-A4-9E-7B-D1-97-8-D6-6F-F8-9F-55-29-56-5C-7D-F6-86-71-9A-6E-7D-2E-DC-DC-55-98-C4-6B-CF-25-5E-48-7E-32-71-61-D0-3F-85-6F-82-95-8E-A6-39-13-A7-B-4B-2F-A-EC-1F-B4-50-11-32-74-5C-59-30-B6-7-6A-B5-C2-9-A8-55-39-AE-63-A3-FF-F-C0-F0-A1-84-BF-20-FB-1B-35-72-D7-E8-3F-BB-56-57-C1-97-EA-EE-7A-85-F5-2E-1E-AC-1-25-49-F4-23-DB-25-3C-CC-0-87-62-7F-64-49-53-F0-90-26-CB-F7-45-1E-77-47-E0-F3-CC-39-C0-A2-74-4C-AA-1D-C6-8D-15-AF-AE-B4-29";
   const CB_TOKEN_VALID_MINUTES = 262800; // 6 months
   const CB_TOKEN_RENEW_TIMEFRAME = 30; // 30 minutes
   const userCredentials = { 'mds': { username: 'mds', password: '1234', role: 'user' } };

   const generateCodebeamerJWT = (username = 'sejin.park') => {
     const now = Math.floor(Date.now() / 1000);
     const expiresAt = now + (CB_TOKEN_VALID_MINUTES * 60);
     
     const payload = {
       iss: 'codeBeamer',
       name: username,
       exp: expiresAt,
       type: 'access',
       iat: now
     };
     
     const token = jwt.sign(payload, CB_JWT_SECRET, { algorithm: 'HS256' });
     return token;
   };

   const isJWTValid = (token) => {
     try {
       const decoded = jwt.verify(token, CB_JWT_SECRET);
       return decoded.exp > Math.floor(Date.now() / 1000);
     } catch (error) {
       return false;
     }
   };

   const performCodebeamerLogin = async (username = 'sejin.park') => {
     try {
       const userCreds = userCredentials[username];
       if (!userCreds) {
         return { success: false, error: 'User not found' };
       }

       const loginPageResponse = await axios.get('http://codebeamer.mdsit.co.kr:3008/login.spr');
       const csrfMatch = loginPageResponse.data.match(/name="_csrf" value="([^"]+)"/);
       const csrfToken = csrfMatch ? csrfMatch[1] : '';
       const loginResponse = await axios.post('http://codebeamer.mdsit.co.kr:3008/login.spr', 
         `user=${userCreds.username}&password=${userCreds.password}&_csrf=${csrfToken}`,
         {
           headers: {
             'Content-Type': 'application/x-www-form-urlencoded',
             'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
           },
           maxRedirects: 0,
           validateStatus: (status) => status < 400
         }
       );

       const cookies = loginResponse.headers['set-cookie'];
       return { success: true, cookies, csrfToken, username: userCreds.username };
       
     } catch (error) {
       console.error('Codebeamer login error:', error.message);
       return { success: false, error: error.message };
     }
   };

   app.get('/codebeamer-access', async (req, res) => {
     try {
       const loginResult = await performCodebeamerLogin('mds');
       
       if (loginResult.success) {
         const autoLoginPage = `
           <!DOCTYPE html>
           <html>
           <head>
             <title>Codebeamer Auto Login - BeamerX</title>
             <style>
               body { 
                 font-family: Arial, sans-serif; 
                 margin: 0;
                 background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                 color: white;
                 display: flex;
                 justify-content: center;
                 align-items: center;
                 height: 100vh;
               }
               .container {
                 text-align: center;
                 background: rgba(255,255,255,0.1);
                 padding: 40px;
                 border-radius: 20px;
                 backdrop-filter: blur(10px);
                 border: 1px solid rgba(255,255,255,0.2);
                 max-width: 500px;
               }
               .spinner { 
                 border: 4px solid rgba(255,255,255,0.3);
                 border-radius: 50%;
                 border-top: 4px solid white;
                 width: 50px;
                 height: 50px;
                 animation: spin 1s linear infinite;
                 margin: 20px auto;
               }
               @keyframes spin {
                 0% { transform: rotate(0deg); }
                 100% { transform: rotate(360deg); }
               }
               .countdown {
                 font-size: 18px;
                 margin: 20px 0;
               }
             </style>
           </head>
           <body>
             <div class="container">
               <div class="spinner"></div>
               <h1><img src="/images/codebeamer_icon.png" alt="Codebeamer" style="width: 30px; height: 30px; vertical-align: middle; margin-right: 10px;"> 자동 로그인</h1>
               <p>사용자 <strong>mds</strong>로 Codebeamer에 자동 로그인합니다...</p>
               <p><span id="countdown">3</span>초 후 자동으로 제출됩니다</p>
             </div>
             
             <form id="loginForm" method="POST" action="http://codebeamer.mdsit.co.kr:3008/login.spr" style="display:none;">
               <input type="hidden" name="_csrf" value="${loginResult.csrfToken}">
               <input type="text" name="user" value="mds">
               <input type="password" name="password" value="1234">
             </form>
             
             <script>
               let countdown = 3;
               const countdownElement = document.getElementById('countdown');
               
               const timer = setInterval(() => {
                 countdown--;
                 countdownElement.textContent = countdown;
                 
                 if (countdown <= 0) {
                   clearInterval(timer);
                   // Auto-submit the login form
                   document.getElementById('loginForm').submit();
                 }
               }, 1000);
             </script>
           </body>
           </html>
         `;
         
         res.send(autoLoginPage);
       } else {
         res.redirect('http://codebeamer.mdsit.co.kr:3008/login.spr');
       }
       
     } catch (error) {
       console.error('Auto login error:', error);
       res.redirect('http://codebeamer.mdsit.co.kr:3008/login.spr');
     }
   });

   app.get('/codebeamer-direct', async (req, res) => {
     try {
       const loginResult = await performCodebeamerLogin();
       
       if (loginResult.success) {
         const directLoginPage = `
           <!DOCTYPE html>
           <html>
           <head>
             <title>Direct Codebeamer Access - BeamerX</title>
             <style>
               body { 
                 font-family: Arial, sans-serif; 
                 margin: 0;
                 background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                 color: white;
                 display: flex;
                 justify-content: center;
                 align-items: center;
                 height: 100vh;
               }
               .container {
                 text-align: center;
                 background: rgba(255,255,255,0.1);
                 padding: 40px;
                 border-radius: 20px;
                 backdrop-filter: blur(10px);
                 border: 1px solid rgba(255,255,255,0.2);
                 max-width: 500px;
               }
               .btn {
                 background: #4CAF50;
                 color: white;
                 padding: 15px 30px;
                 border: none;
                 border-radius: 8px;
                 cursor: pointer;
                 font-size: 16px;
                 margin: 10px;
                 text-decoration: none;
                 display: inline-block;
               }
               .btn:hover {
                 background: #45a049;
               }
             </style>
           </head>
           <body>
             <div class="container">
               <h1><img src="/images/codebeamer_icon.png" alt="Codebeamer" style="width: 30px; height: 30px; vertical-align: middle; margin-right: 10px;"> 직접 접속</h1>
               <p>Codebeamer에 직접 접속합니다</p>
               <p><strong>CSRF Token:</strong> ${loginResult.csrfToken.substring(0, 20)}...</p>
               
               <a href="http://codebeamer.mdsit.co.kr:3008/login.spr" class="btn" onclick="return fillAndSubmit()">자동 로그인</a>
               <a href="http://codebeamer.mdsit.co.kr:3008" class="btn">직접 접속</a>
               
               <script>
                 function fillAndSubmit() {
                   // Open Codebeamer login page
                   const loginWindow = window.open('http://codebeamer.mdsit.co.kr:3008/login.spr', '_blank');
                   
                   // Wait for page to load and fill credentials
                   setTimeout(() => {
                     if (loginWindow) {
                       try {
                         loginWindow.document.querySelector('input[name="user"]').value = 'sejin.park';
                         loginWindow.document.querySelector('input[name="password"]').value = '1234';
                         loginWindow.document.querySelector('form').submit();
                       } catch (e) {
                         console.log('Could not fill form automatically');
                       }
                     }
                   }, 2000);
                   
                   return false;
                 }
               </script>
             </div>
           </body>
           </html>
         `;
         
         res.send(directLoginPage);
       } else {
         res.redirect('http://codebeamer.mdsit.co.kr:3008/login.spr');
       }
       
     } catch (error) {
       console.error('Direct access error:', error);
       res.redirect('http://codebeamer.mdsit.co.kr:3008/login.spr');
     }
   });

   app.get('/api/login-status', async (req, res) => {
     try {
       const loginResult = await performCodebeamerLogin();
       res.json({
         success: loginResult.success,
         hasCsrfToken: !!loginResult.csrfToken,
         error: loginResult.error
       });
     } catch (error) {
       res.json({ success: false, error: error.message });
     }
   });
 
   app.get('/jwt-status', (req, res) => {
     const testToken = generateCodebeamerJWT();
     const status = {
       jwtValid: isJWTValid(testToken),
       tokenExpiry: new Date((Math.floor(Date.now() / 1000) + (CB_TOKEN_VALID_MINUTES * 60)) * 1000).toISOString(),
       validMinutes: CB_TOKEN_VALID_MINUTES,
       renewTimeframe: CB_TOKEN_RENEW_TIMEFRAME
     };
     res.json(status);
   });
   
   app.get('/api/auth/jwt', (req, res) => {
     try {
       const jwtToken = generateCodebeamerJWT('mds');
       res.json({
         success: true,
         token: jwtToken,
         valid: isJWTValid(jwtToken),
         expiry: new Date((Math.floor(Date.now() / 1000) + (CB_TOKEN_VALID_MINUTES * 60)) * 1000).toISOString(),
         codebeamerUrl: 'http://codebeamer.mdsit.co.kr:3008',
         user: 'mds',
         userRole: 'user'
       });
     } catch (error) {
       res.status(500).json({
         success: false,
         error: error.message
       });
     }
   });

   app.get('/api/auth/session', async (req, res) => {
     try {
       const loginResult = await performCodebeamerLogin('mds');
       
       if (loginResult.success) {
         res.json({
           success: true,
           csrfToken: loginResult.csrfToken,
           hasCookies: !!loginResult.cookies,
           codebeamerUrl: 'http://codebeamer.mdsit.co.kr:3008',
           user: 'mds',
           userRole: 'user'
         });
       } else {
         res.json({
           success: false,
           error: loginResult.error
         });
       }
     } catch (error) {
       res.status(500).json({
         success: false,
         error: error.message
       });
     }
   });
  
   app.get('/api/auth/auto-login', (req, res) => {
     try {
       const autoLoginUrl = `${req.protocol}://${req.get('host')}/codebeamer-access`;
       res.json({
         success: true,
         autoLoginUrl: autoLoginUrl,
         codebeamerUrl: 'http://codebeamer.mdsit.co.kr:3008',
         user: 'mds',
         userRole: 'user',
         credentials: {
           username: 'mds',
           password: '1234'
         }
       });
     } catch (error) {
       res.status(500).json({
         success: false,
         error: error.message
       });
     }
   });

   app.post('/api/auth/validate', (req, res) => {
     try {
       const { token } = req.body;
       
       if (!token) {
         return res.status(400).json({
           success: false,
           error: 'Token is required'
         });
       }
       
       const isValid = isJWTValid(token);
  
       let userInfo = null;
       if (isValid) {
         try {
           const decoded = jwt.verify(token, CB_JWT_SECRET);
           userInfo = {
             name: decoded.name,
             role: 'user' 
           };
         } catch (e) {
         }
       }
       
       res.json({
         success: true,
         valid: isValid,
         token: isValid ? token : null,
         user: userInfo
       });
     } catch (error) {
       res.status(500).json({
         success: false,
         error: error.message
       });
     }
   });

   app.post('/api/auth/webhook', (req, res) => {
     try {
       const { event, appId, userId, timestamp } = req.body;       
       console.log(`Auth webhook received: ${event} from app ${appId} for user ${userId} at ${timestamp}`);
       
       res.json({
         success: true,
         message: 'Webhook received',
         event: event,
         timestamp: new Date().toISOString()
       });
     } catch (error) {
       res.status(500).json({
         success: false,
         error: error.message
       });
     }
   });

   app.use('/codebeamer-proxy', createProxyMiddleware({
     target: 'http://codebeamer.mdsit.co.kr:3008',
     changeOrigin: true,
     onProxyReq: (proxyReq, req, res) => {
       const jwtToken = generateCodebeamerJWT();
       proxyReq.setHeader('Authorization', `Bearer ${jwtToken}`);
       proxyReq.setHeader('X-Auth-Token', jwtToken);
       proxyReq.setHeader('X-User', 'sejin.park');
       
       console.log('Proxying request with JWT token:', jwtToken.substring(0, 20) + '...');
     },
     onProxyRes: (proxyRes, req, res) => {
       const jwtToken = generateCodebeamerJWT();
       proxyRes.headers['X-JWT-Token'] = jwtToken;
       proxyRes.headers['X-Auth-Status'] = 'authenticated';
     }
   }));


  app.get('/', async (req, res) => {
    await db.read();
    res.render('index', { apps: apps, platform });
  });
  
  app.get('/apps', async (req, res) => {
    await db.read();
    res.render('apps', { apps: apps, platform });
  });
  
  app.listen(PORT, () => {
    console.log(`BeamerX running at http://localhost:${PORT}`);
  });
}
  
main();
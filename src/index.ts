/*
index.ts
This is the main file for the Auth Inbox Email Worker.
created by: github@TooonyChen
created on: 2024 Oct 07
Last updated: 2024 Oct 07
*/
import { WorkerEntrypoint } from 'cloudflare:workers';
import { RPCEmailMessage } from './rpcEmail';

// @ts-ignore
import indexHtml from './index.html';
import { Email } from 'postal-mime';

interface Env {
    // If you set another name in wrangler.toml as the value for 'binding',
    // replace "DB" with the variable name you defined.
    DB: D1Database;
    FrontEndAdminID: string;
    FrontEndAdminPassword: string;
    barkTokens: string;
    barkUrl: string;
    GoogleAPIKey: string;
    UseBark: string;
    enableParseEmail: string | undefined | null;
    enableWebhook: string | undefined | null;
    webhooks: WebhookInfo[] | string | undefined | null;
}

type WebhookInfo = {
    url: string;
    method: string;
    headers: any;
    body: object;
}

type EmailNotifyData = {
    messageId: string | undefined | null;
    from: string | undefined | null;
    to: string | undefined | null;
    subject: string | undefined | null;
    text: string | undefined | null;
    html: string | undefined | null;
    //----------------------//
    aiTitle: string | undefined | null;
    aiTopic: string | undefined | null;
    aiCode: string | undefined | null;
    aiCodePart: string | undefined | null;
    aiLinkPart: string | undefined | null;
}

const getBooleanValue = (
    value: boolean | string | any
): boolean => {
    if (typeof value === 'boolean') {
        return value;
    }
    if (typeof value === 'string') {
        return value === 'true';
    }
    return false;
};

export default class extends WorkerEntrypoint<Env> {
    async fetch(request: Request): Promise<Response> {

        const url = new URL(request.url);
        if (url.pathname.startsWith('/api/rpcEmail')) {
            try {
                await this.rpcEmail(await request.text());
                return new Response('{"code":"200","message":"ok"}', { status: 200 });
            } catch (e) {
                console.log(`处理异常`, e);
                return new Response('{"code":"500","message":"Internal Error"}', { status: 500 });
            }
        }

        const env: Env = this.env;
        const ctx: ExecutionContext = this.ctx;
        // 将依赖 env 的常量移到函数内部
        const FrontEndAdminID = env.FrontEndAdminID;
        const FrontEndAdminPassword = env.FrontEndAdminPassword;

        // 提取 Authorization 头
        const authHeader = request.headers.get('Authorization');

        // 如果没有 Authorization 头，提示进行身份验证
        if (!authHeader) {
            return new Response('Unauthorized', {
                status: 401,
                headers: {
                    'WWW-Authenticate': 'Basic realm="User Visible Realm"'
                }
            });
        }

        // 检查 Authorization 头是否使用 Basic 认证
        if (!authHeader.startsWith('Basic ')) {
            return new Response('Unauthorized', {
                status: 401,
                headers: {
                    'WWW-Authenticate': 'Basic realm="User Visible Realm"'
                }
            });
        }

        // 解码 base64 编码的凭据
        const base64Credentials = authHeader.substring('Basic '.length);
        const decodedCredentials = atob(base64Credentials);

        // 将凭据分割为用户名和密码
        const [username, password] = decodedCredentials.split(':');

        // 验证凭据
        if (
            username !== FrontEndAdminID ||
            password !== FrontEndAdminPassword
        ) {
            return new Response('Unauthorized', {
                status: 401,
                headers: {
                    'WWW-Authenticate': 'Basic realm="User Visible Realm"'
                }
            });
        }

        try {
            const { results } = await env.DB.prepare(
                'SELECT from_org, to_addr, topic, code, created_at FROM code_mails ORDER BY created_at DESC'
            ).all();

            let dataHtml = '';
            for (const row of results) {
                const codeLinkParts = (row.code as string).split(',');
                let codeLinkContent;

                if (codeLinkParts.length > 1) {
                    const [code, link] = codeLinkParts;
                    codeLinkContent = `${code}<br><a href="${link}" target="_blank">${row.topic}</a>`;
                } else if ((row.code as string).startsWith('http')) {
                    codeLinkContent = `<a href="${row.code}" target="_blank">${row.topic}</a>`;
                } else {
                    codeLinkContent = row.code;
                }

                dataHtml += `<tr>
                    <td>${row.from_org}</td>
                    <td>${row.to_addr}</td>
                    <td>${row.topic}</td>
                    <td>${codeLinkContent}</td>
                    <td>${row.created_at}</td>
                </tr>`;
            }

            let responseHtml = indexHtml
                .replace('{{TABLE_HEADERS}}', `
                    <tr>
                        <th>From</th>
                        <th>To</th>
                        <th>Topic</th>
                        <th>Code/Link</th>
                        <th>Receive Time (GMT)</th>
                    </tr>
                `)
                .replace('{{DATA}}', dataHtml);

            return new Response(responseHtml, {
                headers: {
                    'Content-Type': 'text/html'
                }
            });
        } catch (error) {
            console.error('Error querying database:', error);
            return new Response('Internal Server Error', { status: 500 });
        }
    }

    // 主要功能
    async email(message: ForwardableEmailMessage): Promise<void> {

        const env: Env = this.env;
        const GoogleAPIKey = env.GoogleAPIKey; // "xxxxxxxxxxxxxxxxxxxxxxxx"

        const rawEmail = message instanceof RPCEmailMessage ? (<RPCEmailMessage>message).rawEmail : await new Response(message.raw).text();
        const message_id = message.headers.get('Message-ID');

        // 将电子邮件保存到数据库
        const { success } = await env.DB.prepare(
            `INSERT INTO raw_mails (from_addr, to_addr, raw, message_id)
             VALUES (?, ?, ?, ?)`
        ).bind(
            message.from, message.to, rawEmail, message_id  // 将电子邮件详细信息绑定到 SQL 语句
        ).run();

        // 检查电子邮件是否成功保存
        if (!success) {
            message.setReject(`Failed to save message from ${message.from} to ${message.to}`); // 如果保存失败，则拒绝消息
            console.log(`Failed to save message from ${message.from} to ${message.to}`); // 记录保存失败
        }

        let emailContent = rawEmail;
        let parseEmail: Email = { attachments: [], messageId: '', headers: [], from: { name: '' } };
        if (getBooleanValue(env.enableParseEmail)) {
            console.log(`use postal-mime to parse email content`);
            const { default: PostalMime } = await import('postal-mime');
            parseEmail = await PostalMime.parse(rawEmail);
            emailContent = parseEmail?.text ?? '';
            console.log(`parseEmail =  ${JSON.stringify(parseEmail)}`);
        }

        // 调用AI，让AI抓取验证码，让AI返回`title`和`code`
        // title: 邮件是哪个公司/组织发来的验证码, 比如'Netflix'
        // code: 验证码/链接/密码，比如'123456'or'https://example.com/verify?code=123456',如都有则返回'code, link'
        // topic: 邮件主题，比如'line register verification'
        const aiPrompt = `
  Email content: ${emailContent}.

  Please read the email and extract the following information:
  1. Code/Link/Password from the email (if available).
  2. Organization name (title) from which the email is sent.
  3. A brief summary of the email's topic (e.g., 'line register verification').

  Please provide the following information in JSON format:
  {
    "title": "The organization or company that sent the verification code (e.g., 'Netflix')",
    "code": "The extracted verification code, link, or password (e.g., '123456' or 'https://example.com/verify?code=123456')",
    "topic": "A brief summary of the email's topic (e.g., 'line register verification')",
    "codeExist": 1
  }


  If both a code and a link are present, include both in the 'code' field like this:
  "code": "code, link"

  If there is no code, clickable link, or this is an advertisement email, return:
  {
    "codeExist": 0
  }

  If this is an advertisement, junk, spam email, return:
  {
    "codeExist": 0
  }
`;

        try {
            // 添加重试机制
            const maxRetries = 3;
            let retryCount = 0;
            let extractedData = null;

            while (retryCount < maxRetries && !extractedData) {
                // 调用 Google AI API 来获取 title, code, topic
                const aiResponse = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash-latest:generateContent?key=${GoogleAPIKey}`, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        'contents': [
                            {
                                'parts': [
                                    { 'text': aiPrompt }
                                ]
                            }
                        ]
                    })
                });

                const aiData: any = await aiResponse.json();
                console.log(`AI response attempt ${retryCount + 1}:`, aiData);
                // 检测ai返回格式是否正确
                if (
                    aiData &&
                    aiData.candidates &&
                    aiData.candidates[0] &&
                    aiData.candidates[0].content &&
                    aiData.candidates[0].content.parts &&
                    aiData.candidates[0].content.parts[0]
                ) {
                    let extractedText = aiData.candidates[0].content.parts[0].text;
                    console.log(`Extracted Text before parsing: "${extractedText}"`);

                    // Use regex to extract JSON content from code blocks
                    const jsonMatch = extractedText.match(/```json\s*([\s\S]*?)\s*```/);
                    if (jsonMatch && jsonMatch[1]) {
                        extractedText = jsonMatch[1].trim();
                        console.log(`Extracted JSON Text: "${extractedText}"`);
                    } else {
                        // If no code block, assume the entire text is JSON
                        extractedText = extractedText.trim();
                        console.log(`Assuming entire text is JSON: "${extractedText}"`);
                    }

                    // Parse
                    try {
                        extractedData = JSON.parse(extractedText);
                        console.log(`Parsed Extracted Data:`, extractedData);
                    } catch (parseError) {
                        console.error('JSON parsing error:', parseError);
                        console.log(`Problematic JSON Text: "${extractedText}"`);
                    }

                } else {
                    console.error('AI response is missing expected data structure');
                }

                if (!extractedData) {
                    retryCount++;
                    if (retryCount < maxRetries) {
                        console.log('Retrying AI request...');
                    } else {
                        console.error('Max retries reached. Unable to get valid AI response.');
                    }
                }
            }

            // extract formatted data
            if (extractedData) {
                if (extractedData.codeExist === 1) {
                    const title = extractedData.title || 'Unknown Organization';
                    const code = extractedData.code || 'No Code Found';
                    const topic = extractedData.topic || 'No Topic Found';

                    // save extracted data to the database
                    const { success: codeMailSuccess } = await env.DB.prepare(
                        `INSERT INTO code_mails (from_addr, from_org, to_addr, code, topic, message_id)
                         VALUES (?, ?, ?, ?, ?, ?)`
                    ).bind(
                        message.from, title, message.to, code, topic, message_id
                    ).run();

                    if (!codeMailSuccess) {
                        message.setReject(`Failed to save extracted code for message from ${message.from} to ${message.to}`);
                        console.log(`Failed to save extracted code for message from ${message.from} to ${message.to}`);
                    }

                    let aiCode = '', aiLink = '';
                    const codeLinkParts = (code as string).split(',');
                    if (codeLinkParts.length > 1) {
                        const [codePart, linkPart] = codeLinkParts;
                        aiCode = codePart;
                        aiLink = linkPart;
                    } else if ((code as string).startsWith('http')) {
                        aiLink = (code as string);
                    } else {
                        aiCode = (code as string);
                    }

                    const emailNotifyData: EmailNotifyData = {
                        messageId: message_id ?? '',
                        from: message.from ?? '',
                        to: message.to,
                        subject: parseEmail.subject ?? '',
                        text: parseEmail.text ?? '',
                        html: parseEmail.html ?? '',
                        aiTitle: title ?? '',
                        aiTopic: topic ?? '',
                        aiCode: code,
                        aiCodePart: aiCode,
                        aiLinkPart: aiLink
                    };

                    await this.notify(env, emailNotifyData);

                } else {
                    console.log('No code found in this email, skipping Bark notification.');
                }
            } else {
                console.error('Failed to extract data from AI response after retries.');
            }
        } catch (e) {
            console.error('Error calling AI or saving to database:', e);
        }
    }

    async notify(env: Env, emailNotifyData: EmailNotifyData) {
        // Send title and code to Bark using GET request for each token
        const useBark = env.UseBark.toLowerCase() === 'true'; // true or false
        if (useBark) {
            const barkUrl = env.barkUrl; // "https://api.day.app"
            // [token1, token2]
            const barkTokens = env.barkTokens
                .replace(/^\[|\]$/g, '')
                .split(',')
                .map(token => token.trim());

            const barkUrlEncodedTitle = encodeURIComponent(emailNotifyData.aiTitle as string);
            const barkUrlEncodedCode = encodeURIComponent(emailNotifyData.aiCode as string);

            for (const token of barkTokens) {
                const barkRequestUrl = `${barkUrl}/${token}/${barkUrlEncodedTitle}/${barkUrlEncodedCode}`;

                const barkResponse = await fetch(barkRequestUrl, {
                    method: 'GET'
                });

                if (barkResponse.ok) {
                    console.log(`Successfully sent notification to Bark for token ${token} for message from ${emailNotifyData.from} to ${emailNotifyData.to}`);
                    const responseData = await barkResponse.json();
                    console.log('Bark response:', responseData);
                } else {
                    console.error(`Failed to send notification to Bark for token ${token}: ${barkResponse.status} ${barkResponse.statusText}`);
                }
            }
        }

        if (getBooleanValue(env.enableWebhook) && env.webhooks) {
            if (!Array.isArray(env.webhooks)) {
                try {
                    env.webhooks = JSON.parse(env.webhooks);
                } catch (e) {
                    console.error('webhooks configuration error:', e);
                    env.webhooks = [];
                }
            }

            const webhooks: WebhookInfo[] = env.webhooks as WebhookInfo[];
            for (const webhook of webhooks) {
                try {
                    console.error(`exec webhook , webhook= ${JSON.stringify(webhook)}`);
                    const res = await this.sendWebhook(webhook, emailNotifyData);
                    if (!res.success) {
                        console.error(`exec webhook fail, webhook= ${JSON.stringify(webhook)}, fail message=${res.message}`);
                    }
                } catch (e) {
                    console.error(`exec webhook exception, webhook= ${JSON.stringify(webhook)}`, e);
                }
            }
        }
    }

    async sendWebhook(webhook: WebhookInfo, emailNotifyData: EmailNotifyData) {
        let body = JSON.stringify(webhook.body ?? '');
        let url = webhook.url;
        for (const key of Object.keys(emailNotifyData)) {
            /* eslint-disable no-useless-escape */
            body = body.replace(
                new RegExp(`\\$\\{${key}\\}`, 'g'),
                JSON.stringify(
                    emailNotifyData[key as keyof EmailNotifyData]
                ).replace(/^"(.*)"$/, '\$1')
            );
            url = url.replace(
                new RegExp(`\\$\\{${key}\\}`, 'g'),
                encodeURIComponent(JSON.stringify(
                    emailNotifyData[key as keyof EmailNotifyData]
                ).replace(/^"(.*)"$/, '\$1'))
            );
        }
        console.log('send webhook', webhook.url, webhook.method, webhook.headers, body);
        let init = body.length > 0 ? {
            method: webhook.method,
            headers: webhook.headers,
            body: body.replace(/^"(.*)"$/, '\$1')
        } : {
            method: webhook.method,
            headers: webhook.headers
        };

        const response = await fetch(url, init);
        if (!response.ok) {
            console.log('send webhook error', response.status, response.statusText);
            return { success: false, message: `send webhook error: ${response.status} ${response.statusText}` };
        }
        return { success: true };
    }

    // 暴露rpc接口，处理来自其他worker的邮件请求
    async rpcEmail(requestBody: string): Promise<void> {
        console.log(`Received RPC email , request body: ${requestBody}`);
        const bodyObject = JSON.parse(requestBody);
        const headersObject = bodyObject.headers;
        const headers = new Headers(headersObject);
        const rpcEmailMessage: RPCEmailMessage = new RPCEmailMessage(bodyObject.from, bodyObject.to, bodyObject.rawEmail, headers);
        await this.email(rpcEmailMessage);
    }
}

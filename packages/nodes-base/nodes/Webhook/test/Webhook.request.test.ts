import type { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { REDACTED, type IDataObject, type INode, type IWebhookFunctions } from 'n8n-workflow';
import { Readable } from 'stream';
import { mock } from 'vitest-mock-extended';

import { Wait } from '../../Wait/Wait.node';
import { Webhook } from '../Webhook.node';

describe('Webhook request data', () => {
	const credentialValue = 'test-credential-value';
	const cases = [
		{
			authentication: 'headerAuth',
			header: 'x-request-auth',
			value: credentialValue,
			credentials: { name: 'X-Request-Auth', value: credentialValue },
		},
		{
			authentication: 'basicAuth',
			header: 'authorization',
			value: `Basic ${Buffer.from(`user:${credentialValue}`).toString('base64')}`,
			credentials: { user: 'user', password: credentialValue },
		},
		{
			authentication: 'bearerAuth',
			header: 'authorization',
			value: `Bearer ${credentialValue}`,
			credentials: { token: credentialValue },
		},
		{
			authentication: 'jwtAuth',
			header: 'authorization',
			value: `Bearer ${jwt.sign({ sub: 'test-user' }, credentialValue, { noTimestamp: true })}`,
			credentials: { keyType: 'passphrase', secret: credentialValue, algorithm: 'HS256' },
		},
	];

	function setup(
		options: IDataObject = {},
		auth = cases[0],
		responseMode = 'onReceived',
		resume = 'webhook',
	) {
		const request = Object.assign(Readable.from([Buffer.from('request bytes')]), {
			headers: { [auth.header]: auth.value, 'x-business-id': 'order-123' },
			params: { id: '123' },
			query: { page: '1' },
			body: { order: '123' },
			method: 'POST',
			contentType: 'application/json',
			ips: [],
			ip: '127.0.0.1',
		}) as unknown as Request;
		const response = mock<Response>();
		const context = mock<IWebhookFunctions>({ nodeHelpers: mock() });
		context.getRequestObject.mockReturnValue(request);
		context.getResponseObject.mockReturnValue(response);
		context.getHeaderData.mockReturnValue(request.headers);
		context.getNode.mockReturnValue(
			mock<INode>({
				name: 'Webhook',
				type: 'n8n-nodes-base.webhook',
				typeVersion: 2,
				parameters: { options },
			}),
		);
		context.getNodeParameter.mockImplementation((name) => {
			if (name === 'options') return options;
			if (name === 'authentication' || name === 'incomingAuthentication')
				return auth.authentication;
			if (name === 'responseMode') return responseMode;
			if (name === 'httpMethod') return 'POST';
			if (name === 'resume') return resume;
			if (name === 'options.showHeaders') return options.showHeaders ?? false;
			if (name === 'formFields.values') return [{ fieldLabel: 'Order', fieldType: 'text' }];
			return undefined;
		});
		context.getCredentials.mockResolvedValue(auth.credentials);
		context.getChildNodes.mockReturnValue([]);
		context.getMode.mockReturnValue('webhook');
		context.getBodyData.mockImplementation(() => request.body);
		context.getWorkflowSettings.mockReturnValue({});
		context.getNodeWebhookUrl.mockReturnValue('https://example.test/webhook/request');
		context.nodeHelpers.copyBinaryFile.mockResolvedValue({
			data: 'cmVxdWVzdCBieXRlcw==',
			mimeType: 'application/octet-stream',
		});
		// WebhookContext retains these request objects before authentication runs.
		const input = [
			{
				json: {
					headers: request.headers,
					body: request.body,
					params: request.params,
					query: request.query,
				},
			},
		];
		return { context, request, response, input };
	}

	it.each(cases)('stores the authenticated request data for $authentication', async (auth) => {
		const { context, request, input } = setup({}, auth);
		const originalHeaders = request.headers;
		const result = await new Webhook().webhook(context);
		const output = result.workflowData?.[0][0].json;

		expect(request.headers).toBe(originalHeaders);
		expect(input[0].json.headers).toEqual({
			[auth.header]: REDACTED,
			'x-business-id': 'order-123',
		});
		expect(output).toMatchObject({
			headers: input[0].json.headers,
			body: { order: '123' },
			params: { id: '123' },
			query: { page: '1' },
		});
		expect(JSON.stringify({ input, output })).not.toContain(auth.value);
		if (auth.authentication === 'jwtAuth') expect(output?.jwtPayload).toEqual({ sub: 'test-user' });
	});

	it.each(['binary', 'multipart', 'rawBody', 'streaming'])(
		'keeps the request data in %s mode',
		async (mode) => {
			const { context, request, input, response } = setup(
				{ binaryData: mode === 'binary', rawBody: mode === 'rawBody' },
				cases[0],
				mode === 'streaming' ? 'streaming' : 'onReceived',
			);
			if (mode === 'multipart') {
				request.contentType = 'multipart/form-data';
				request.body = { data: { order: '123' }, files: {} };
			}
			if (mode === 'rawBody') request.rawBody = Buffer.from('request bytes');

			const result = await new Webhook().webhook(context);
			const output = result.workflowData?.[0][0];
			expect(output?.json.headers).toEqual({
				'x-request-auth': REDACTED,
				'x-business-id': 'order-123',
			});
			expect(output?.json.body).toEqual(mode === 'binary' ? {} : { order: '123' });
			expect(JSON.stringify({ input, output })).not.toContain(credentialValue);
			if (mode === 'binary' || mode === 'rawBody')
				expect(output?.binary?.data.data).toBe('cmVxdWVzdCBieXRlcw==');
			if (mode === 'streaming') expect(response.flushHeaders).toHaveBeenCalled();
		},
	);

	it('updates the retained input before the request filter returns', async () => {
		const { context, input } = setup({ onlyRunIf: '={{ false }}' });
		context.evaluateExpression.mockReturnValue(false);

		expect(await new Webhook().webhook(context)).toEqual({});
		expect(input[0].json.headers['x-request-auth']).toBe(REDACTED);
		expect(input[0].json.body).toEqual({ order: '123' });
	});

	it('keeps headers that the configured authentication does not use', async () => {
		const { context, request } = setup();
		request.headers.authorization = 'Bearer caller-owned-value';

		const result = await new Webhook().webhook(context);

		expect(result.workflowData?.[0][0].json.headers).toMatchObject({
			'x-request-auth': REDACTED,
			authorization: 'Bearer caller-owned-value',
		});
	});

	it.each(cases)('rejects an unmatched credential for $authentication', async (auth) => {
		const { context, request, response } = setup({}, auth);
		request.headers[auth.header] = 'unmatched-value';

		expect(await new Webhook().webhook(context)).toEqual({ noWebhookResponse: true });
		expect(response.writeHead).toHaveBeenCalledWith(
			expect.any(Number),
			expect.objectContaining({ 'WWW-Authenticate': 'Basic realm="Webhook"' }),
		);
		expect(response.writeHead.mock.calls[0][0]).toBeGreaterThanOrEqual(400);
	});

	it('keeps the complete headers when authentication is disabled', async () => {
		const { context, request } = setup({}, { ...cases[0], authentication: 'none' });
		const headers = { ...request.headers };

		const result = await new Webhook().webhook(context);

		expect(result.workflowData?.[0][0].json.headers).toEqual(headers);
		expect(context.getCredentials).not.toHaveBeenCalled();
	});

	it('updates retained input when identity setup ends with an error', async () => {
		const { context, input } = setup({}, { ...cases[2], authentication: 'n8nOAuth2' });
		context.getWebhookResourceUrl.mockReturnValue('https://example.test/webhook/request');
		context.validateN8nOAuth2Token.mockResolvedValue({
			valid: true,
			user: { id: 'test-user', email: 'user@example.test', firstName: 'Test', lastName: 'User' },
		});
		context.establishTriggerIdentity.mockRejectedValue(new Error('Identity setup failed'));

		await expect(new Webhook().webhook(context)).rejects.toThrow('Identity setup failed');

		expect(context.validateN8nOAuth2Token).toHaveBeenCalledWith(
			credentialValue,
			'https://example.test/webhook/request?method=POST',
		);
		expect(input[0].json.headers.authorization).toBe(REDACTED);
	});

	it('uses the same request handling when a webhook resumes a wait', async () => {
		const { context, input } = setup();
		context.getNode.mockReturnValue(mock<INode>({ type: 'n8n-nodes-base.wait', typeVersion: 1.1 }));

		const result = await new Wait().webhook(context);

		expect(result.workflowData?.[0][0].json.headers).toEqual(input[0].json.headers);
		expect(JSON.stringify({ input, output: result.workflowData })).not.toContain(credentialValue);
	});

	it.each([true, false])(
		'stores form resume data with showHeaders set to %s',
		async (showHeaders) => {
			const { context, request, input } = setup({ showHeaders }, cases[0], 'onReceived', 'form');
			context.getNode.mockReturnValue(
				mock<INode>({ type: 'n8n-nodes-base.wait', typeVersion: 1.1 }),
			);
			request.contentType = 'multipart/form-data';
			request.body = { data: { 'field-0': '123' }, files: {} };
			input[0].json.body = request.body;

			const result = await new Wait().webhook(context);
			const output = result.workflowData?.[0][0].json;

			expect(output).toMatchObject({ Order: '123', formMode: 'production' });
			expect(input[0].json.headers['x-request-auth']).toBe(REDACTED);
			if (showHeaders) expect(output?.headers).toEqual(input[0].json.headers);
			else expect(output?.headers).toBeUndefined();
			expect(JSON.stringify({ input, output })).not.toContain(credentialValue);
		},
	);
});

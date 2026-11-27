import { APIGatewayProxyHandler } from 'aws-lambda';
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import {
  DynamoDBDocumentClient,
  GetCommand,
  ScanCommand,
  QueryCommand,
  PutCommand,
  UpdateCommand,
  DeleteCommand,
  BatchWriteCommand,
} from '@aws-sdk/lib-dynamodb';
import { randomUUID } from 'crypto';
import { getUserRole, checkPermission, isBulkAllowed, type Role } from './rbac';

const client = new DynamoDBClient({ region: process.env.AWS_REGION || 'ap-northeast-1' });
const docClient = DynamoDBDocumentClient.from(client);

const TABLE_NAME = process.env.MAIN_TABLE!;

interface AuthContext {
  userId: string;
  role: Role;
}

interface ApiResponse<T = unknown> {
  statusCode: number;
  body: string;
}

function response<T>(statusCode: number, data: T): ApiResponse {
  return {
    statusCode,
    body: JSON.stringify(data),
  };
}

function errorResponse(statusCode: number, message: string): ApiResponse {
  return response(statusCode, { error: message });
}

async function getAuthContext(event: any): Promise<AuthContext> {
  const userId = event.requestContext?.authorizer?.claims?.sub || event.headers?.['x-user-id'];
  if (!userId) {
    throw new Error('UNAUTHORIZED');
  }
  const role = await getUserRole(userId, docClient);
  return { userId, role };
}

async function createAuditLog(userId: string, action: string, details: Record<string, unknown>): Promise<void> {
  const auditId = randomUUID();
  const now = new Date().toISOString();
  await docClient.send(
    new PutCommand({
      TableName: TABLE_NAME,
      Item: {
        pk: 'AUDIT',
        sk: `${now}#${auditId}`,
        userId,
        action,
        details,
        timestamp: now,
      },
    })
  );
}

function validateUUID(id: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id);
}

function validateEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// ============================================================================
// GET /resources - リソース一覧取得
// ============================================================================
export const getResources: APIGatewayProxyHandler = async (event) => {
  try {
    const auth = await getAuthContext(event);

    // viewer ロールでもレポート閲覧権限があれば取得可能
    if (!checkPermission(auth.role, 'レポート閲覧')) {
      return errorResponse(403, 'FORBIDDEN');
    }

    const result = await docClient.send(
      new ScanCommand({
        TableName: TABLE_NAME,
        FilterExpression: 'attribute_exists(#type)',
        ExpressionAttributeNames: { '#type': 'type' },
      })
    );

    return response(200, {
      resources: result.Items || [],
      count: result.Count || 0,
    });
  } catch (error: any) {
    if (error.message === 'UNAUTHORIZED') {
      return errorResponse(401, 'UNAUTHORIZED');
    }
    if (error.message === 'FORBIDDEN') {
      return errorResponse(403, 'FORBIDDEN');
    }
    console.error('Error:', error);
    return errorResponse(500, 'Internal Server Error');
  }
};

// ============================================================================
// POST /api/{tableIndex}/bulk - 一括インポート
// ============================================================================
export const bulkImport: APIGatewayProxyHandler = async (event) => {
  try {
    const auth = await getAuthContext(event);

    if (!isBulkAllowed(auth.role)) {
      return errorResponse(403, 'FORBIDDEN: Bulk import not allowed for this role');
    }

    const body = JSON.parse(event.body || '{}');
    const items = body.items as Record<string, unknown>[];

    if (!Array.isArray(items) || items.length === 0) {
      return errorResponse(400, 'Invalid request: items must be a non-empty array');
    }

    const now = new Date().toISOString();
    const processedItems = items.map((item) => ({
      ...item,
      id: (item as any).id || randomUUID(),
      createdAt: now,
      updatedAt: now,
    }));

    const chunks: Record<string, unknown>[][] = [];
    for (let i = 0; i < processedItems.length; i += 25) {
      chunks.push(processedItems.slice(i, i + 25));
    }

    let imported = 0;
    const errors: string[] = [];

    for (const chunk of chunks) {
      const requests = chunk.map((item) => ({
        PutRequest: {
          Item: {
            pk: (item as any).pk || `ITEM#${(item as any).id}`,
            sk: (item as any).sk || 'DATA',
            ...item,
          },
        },
      }));

      try {
        await docClient.send(
          new BatchWriteCommand({
            RequestItems: {
              [TABLE_NAME]: requests,
            },
          })
        );
        imported += chunk.length;
      } catch (error: any) {
        errors.push(`Batch write failed: ${error.message}`);
      }
    }

    await createAuditLog(auth.userId, 'BULK_IMPORT', {
      imported,
      failed: items.length - imported,
      totalRequested: items.length,
    });

    return response(200, {
      imported,
      failed: items.length - imported,
      errors,
    });
  } catch (error: any) {
    if (error.message === 'UNAUTHORIZED') {
      return errorResponse(401, 'UNAUTHORIZED');
    }
    if (error.message === 'FORBIDDEN') {
      return errorResponse(403, 'FORBIDDEN');
    }
    console.error('Error:', error);
    return errorResponse(500, 'Internal Server Error');
  }
};

// ============================================================================
// POST /repairs - 修繕依頼作成
// ============================================================================
export const createRepair: APIGatewayProxyHandler = async (event) => {
  try {
    const auth = await getAuthContext(event);

    if (!checkPermission(auth.role, '修繕依頼作成')) {
      return errorResponse(403, 'FORBIDDEN');
    }

    const body = JSON.parse(event.body || '{}');
    const { title, content, priority, categoryId } = body;

    if (!title || !content || !priority) {
      return errorResponse(400, 'Missing required fields: title, content, priority');
    }

    const repairId = randomUUID();
    const now = new Date().toISOString();

    const item = {
      pk: `REPAIR#${repairId}`,
      sk: 'DATA',
      id: repairId,
      title,
      content,
      priority,
      categoryId,
      status: '未対応',
      requesterId: auth.userId,
      createdAt: now,
      updatedAt: now,
      createdBy: auth.userId,
    };

    await docClient.send(
      new PutCommand({
        TableName: TABLE_NAME,
        Item: item,
      })
    );

    await createAuditLog(auth.userId, 'CREATE_REPAIR', { repairId });

    return response(201, item);
  } catch (error: any) {
    if (error.message === 'UNAUTHORIZED') {
      return errorResponse(401, 'UNAUTHORIZED');
    }
    if (error.message === 'FORBIDDEN') {
      return errorResponse(403, 'FORBIDDEN');
    }
    console.error('Error:', error);
    return errorResponse(500, 'Internal Server Error');
  }
};

// ============================================================================
// GET /repairs/{repairId} - 修繕依頼詳細取得
// ============================================================================
export const getRepair: APIGatewayProxyHandler = async (event) => {
  try {
    const auth = await getAuthContext(event);
    const repairId = event.pathParameters?.repairId;

    if (!repairId || !validateUUID(repairId)) {
      return errorResponse(400, 'Invalid repair ID');
    }

    const result = await docClient.send(
      new GetCommand({
        TableName: TABLE_NAME,
        Key: { pk: `REPAIR#${repairId}`, sk: 'DATA' },
      })
    );

    if (!result.Item) {
      return errorResponse(404, 'Repair not found');
    }

    return response(200, result.Item);
  } catch (error: any) {
    if (error.message === 'UNAUTHORIZED') {
      return errorResponse(401, 'UNAUTHORIZED');
    }
    console.error('Error:', error);
    return errorResponse(500, 'Internal Server Error');
  }
};

// ============================================================================
// GET /repairs - 修繕依頼一覧取得
// ============================================================================
export const listRepairs: APIGatewayProxyHandler = async (event) => {
  try {
    const auth = await getAuthContext(event);

    const result = await docClient.send(
      new QueryCommand({
        TableName: TABLE_NAME,
        KeyConditionExpression: 'begins_with(pk, :pk)',
        ExpressionAttributeValues: { ':pk': 'REPAIR#' },
      })
    );

    return response(200, {
      repairs: result.Items || [],
      count: result.Count || 0,
    });
  } catch (error: any) {
    if (error.message === 'UNAUTHORIZED') {
      return errorResponse(401, 'UNAUTHORIZED');
    }
    console.error('Error:', error);
    return errorResponse(500, 'Internal Server Error');
  }
};

// ============================================================================
// PUT /repairs/{repairId} - 修繕依頼更新
// ============================================================================
export const updateRepair: APIGatewayProxyHandler = async (event) => {
  try {
    const auth = await getAuthContext(event);

    if (!checkPermission(auth.role, '修繕依頼編集')) {
      return errorResponse(403, 'FORBIDDEN');
    }

    const repairId = event.pathParameters?.repairId;
    if (!repairId || !validateUUID(repairId)) {
      return errorResponse(400, 'Invalid repair ID');
    }

    const body = JSON.parse(event.body || '{}');
    const now = new Date().toISOString();

    const updateExpression = Object.keys(body)
      .filter((key) => key !== 'id' && key !== 'pk' && key !== 'sk')
      .map((key, index) => `${key} = :val${index}`)
      .join(', ');

    const expressionAttributeValues = Object.values(body)
      .filter((_, index) => !['id', 'pk', 'sk'].includes(Object.keys(body)[index]))
      .reduce(
        (acc, val, index) => {
          acc[`:val${index}`] = val;
          return acc;
        },
        { ':updatedAt': now } as Record<string, unknown>
      );

    await docClient.send(
      new UpdateCommand({
        TableName: TABLE_NAME,
        Key: { pk: `REPAIR#${repairId}`, sk: 'DATA' },
        UpdateExpression: `SET ${updateExpression}, updatedAt = :updatedAt`,
        ExpressionAttributeValues: expressionAttributeValues,
        ReturnValues: 'ALL_NEW',
      })
    );

    await createAuditLog(auth.userId, 'UPDATE_REPAIR', { repairId, changes: body });

    const result = await docClient.send(
      new GetCommand({
        TableName: TABLE_NAME,
        Key: { pk: `REPAIR#${repairId}`, sk: 'DATA' },
      })
    );

    return response(200, result.Item);
  } catch (error: any) {
    if (error.message === 'UNAUTHORIZED') {
      return errorResponse(401, 'UNAUTHORIZED');
    }
    if (error.message === 'FORBIDDEN') {
      return errorResponse(403, 'FORBIDDEN');
    }
    console.error('Error:', error);
    return errorResponse(500, 'Internal Server Error');
  }
};

// ============================================================================
// DELETE /repairs/{repairId} - 修繕依頼削除
// ============================================================================
export const deleteRepair: APIGatewayProxyHandler = async (event) => {
  try {
    const auth = await getAuthContext(event);

    if (!checkPermission(auth.role, '修繕依頼削除')) {
      return errorResponse(403, 'FORBIDDEN');
    }

    const repairId = event.pathParameters?.repairId;
    if (!repairId || !validateUUID(repairId)) {
      return errorResponse(400, 'Invalid repair ID');
    }

    await docClient.send(
      new DeleteCommand({
        TableName: TABLE_NAME,
        Key: { pk: `REPAIR#${repairId}`, sk: 'DATA' },
      })
    );

    await createAuditLog(auth.userId, 'DELETE_REPAIR', { repairId });

    return response(204, {});
  } catch (error: any) {
    if (error.message === 'UNAUTHORIZED') {
      return errorResponse(401, 'UNAUTHORIZED');
    }
    if (error.message === 'FORBIDDEN') {
      return errorResponse(403, 'FORBIDDEN');
    }
    console.error('Error:', error);
    return errorResponse(500, 'Internal Server Error');
  }
};

// ============================================================================
// POST /users - ユーザー作成
// ============================================================================
export const createUser: APIGatewayProxyHandler = async (event) => {
  try {
    const auth = await getAuthContext(event);

    if (auth.role !== 'admin') {
      return errorResponse(403, 'FORBIDDEN: Only admin can create users');
    }

    const body = JSON.parse(event.body || '{}');
    const { loginId, password, userName, email, role } = body;

    if (!loginId || !password || !userName || !role) {
      return errorResponse(400, 'Missing required fields: loginId, password, userName, role');
    }

    if (email && !validateEmail(email)) {
      return errorResponse(400, 'Invalid email format');
    }

    const userId = randomUUID();
    const now = new Date().toISOString();

    // Simple hash simulation (in production, use bcrypt)
    const passwordHash = Buffer.from(password).toString('base64');

    const item = {
      pk: `USER#${userId}`,
      sk: 'PROFILE',
      id: userId,
      loginId,
      passwordHash,
      userName,
      email,
      role,
      isActive: true,
      createdAt: now,
      updatedAt: now,
      createdBy: auth.userId,
    };

    await docClient.send(
      new PutCommand({
        TableName: TABLE_NAME,
        Item: item,
      })
    );

    await createAuditLog(auth.userId, 'CREATE_USER', { userId, loginId });

    return response(201, { ...item, passwordHash: undefined });
  } catch (error: any) {
    if (error.message === 'UNAUTHORIZED') {
      return errorResponse(401, 'UNAUTHORIZED');
    }
    if (error.message === 'FORBIDDEN') {
      return errorResponse(403, 'FORBIDDEN');
    }
    console.error('Error:', error);
    return errorResponse(500, 'Internal Server Error');
  }
};

// ============================================================================
// GET /users/{userId} - ユーザー詳細取得
// ============================================================================
export const getUser: APIGatewayProxyHandler = async (event) => {
  try {
    const auth = await getAuthContext(event);
    const userId = event.pathParameters?.userId;

    if (!userId || !validateUUID(userId)) {
      return errorResponse(400, 'Invalid user ID');
    }

    if (auth.role !== 'admin' && auth.userId !== userId) {
      return errorResponse(403, 'FORBIDDEN');
    }

    const result = await docClient.send(
      new GetCommand({
        TableName: TABLE_NAME,
        Key: { pk: `USER#${userId}`, sk: 'PROFILE' },
      })
    );

    if (!result.Item) {
      return errorResponse(404, 'User not found');
    }

    return response(200, { ...result.Item, passwordHash: undefined });
  } catch (error: any) {
    if (error.message === 'UNAUTHORIZED') {
      return errorResponse(401, 'UNAUTHORIZED');
    }
    if (error.message === 'FORBIDDEN') {
      return errorResponse(403, 'FORBIDDEN');
    }
    console.error('Error:', error);
    return errorResponse(500, 'Internal Server Error');
  }
};

// ============================================================================
// GET /users - ユーザー一覧取得
// ============================================================================
export const listUsers: APIGatewayProxyHandler = async (event) => {
  try {
    const auth = await getAuthContext(event);

    if (auth.role !== 'admin') {
      return errorResponse(403, 'FORBIDDEN: Only admin can list users');
    }

    const result = await docClient.send(
      new QueryCommand({
        TableName: TABLE_NAME,
        KeyConditionExpression: 'begins_with(pk, :pk)',
        ExpressionAttributeValues: { ':pk': 'USER#' },
      })
    );

    const users = (result.Items || []).map((item) => ({ ...item, passwordHash: undefined }));

    return response(200, {
      users,
      count: result.Count || 0,
    });
  } catch (error: any) {
    if (error.message === 'UNAUTHORIZED') {
      return errorResponse(401, 'UNAUTHORIZED');
    }
    if (error.message === 'FORBIDDEN') {
      return errorResponse(403, 'FORBIDDEN');
    }
    console.error('Error:', error);
    return errorResponse(500, 'Internal Server Error');
  }
};

// ============================================================================
// POST /estimates - 見積書作成
// ============================================================================
export const createEstimate: APIGatewayProxyHandler = async (event) => {
  try {
    const auth = await getAuthContext(event);

    if (!checkPermission(auth.role, '修繕依頼作成')) {
      return errorResponse(403, 'FORBIDDEN');
    }

    const body = JSON.parse(event.body || '{}');
    const { repairId, estimateNumber, workContent, taxExcludedAmount, taxAmount } = body;

    if (!repairId || !estimateNumber || !workContent || taxExcludedAmount === undefined || taxAmount === undefined) {
      return errorResponse(400, 'Missing required fields');
    }

    const estimateId = randomUUID();
    const now = new Date().toISOString();
    const totalAmount = taxExcludedAmount + taxAmount;

    const item = {
      pk: `ESTIMATE#${estimateId}`,
      sk: 'DATA',
      id: estimateId,
      repairId,
      estimateNumber,
      workContent,
      taxExcludedAmount,
      taxAmount,
      totalAmount,
      status: '未承認',
      createdAt: now,
      updatedAt: now,
      createdBy: auth.userId,
    };

    await docClient.send(
      new PutCommand({
        TableName: TABLE_NAME,
        Item: item,
      })
    );

    await createAuditLog(auth.userId, 'CREATE_ESTIMATE', { estimateId, repairId });

    return response(201, item);
  } catch (error: any) {
    if (error.message === 'UNAUTHORIZED') {
      return errorResponse(401, 'UNAUTHORIZED');
    }
    if (error.message === 'FORBIDDEN') {
      return errorResponse(403, 'FORBIDDEN');
    }
    console.error('Error:', error);
    return errorResponse(500, 'Internal Server Error');
  }
};

// ============================================================================
// GET /estimates/{estimateId} - 見積書詳細取得
// ============================================================================
export const getEstimate: APIGatewayProxyHandler = async (event) => {
  try {
    const auth = await getAuthContext(event);
    const estimateId = event.pathParameters?.estimateId;

    if (!estimateId || !validateUUID(estimateId)) {
      return errorResponse(400, 'Invalid estimate ID');
    }

    const result = await docClient.send(
      new GetCommand({
        TableName: TABLE_NAME,
        Key: { pk: `ESTIMATE#${estimateId}`, sk: 'DATA' },
      })
    );

    if (!result.Item) {
      return errorResponse(404, 'Estimate not found');
    }

    return response(200, result.Item);
  } catch (error: any) {
    if (error.message === 'UNAUTHORIZED') {
      return errorResponse(401, 'UNAUTHORIZED');
    }
    console.error('Error:', error);
    return errorResponse(500, 'Internal Server Error');
  }
};

// ============================================================================
// PUT /estimates/{estimateId}/approve - 見積書承認
// ============================================================================
export const approveEstimate: APIGatewayProxyHandler = async (event) => {
  try {
    const auth = await getAuthContext(event);

    if (!checkPermission(auth.role, '見積書承認')) {
      return errorResponse(403, 'FORBIDDEN');
    }

    const estimateId = event.pathParameters?.estimateId;
    if (!estimateId || !validateUUID(estimateId)) {
      return errorResponse(400, 'Invalid estimate ID');
    }

    const now = new Date().toISOString();

    await docClient.send(
      new UpdateCommand({
        TableName: TABLE_NAME,
        Key: { pk: `ESTIMATE#${estimateId}`, sk: 'DATA' },
        UpdateExpression: 'SET #status = :status, updatedAt = :updatedAt',
        ExpressionAttributeNames: { '#status': 'status' },
        ExpressionAttributeValues: {
          ':status': '承認',
          ':updatedAt': now,
        },
        ReturnValues: 'ALL_NEW',
      })
    );

    await createAuditLog(auth.userId, 'APPROVE_ESTIMATE', { estimateId });

    const result = await docClient.send(
      new GetCommand({
        TableName: TABLE_NAME,
        Key: { pk: `ESTIMATE#${estimateId}`, sk: 'DATA' },
      })
    );

    return response(200, result.Item);
  } catch (error: any) {
    if (error.message === 'UNAUTHORIZED') {
      return errorResponse(401, 'UNAUTHORIZED');
    }
    if (error.message === 'FORBIDDEN') {
      return errorResponse(403, 'FORBIDDEN');
    }
    console.error('Error:', error);
    return errorResponse(500, 'Internal Server Error');
  }
};

// ============================================================================
// POST /inspections - 立会い記録作成
// ============================================================================
export const createInspection: APIGatewayProxyHandler = async (event) => {
  try {
    const auth = await getAuthContext(event);

    if (!checkPermission(auth.role, '立会い記録作成')) {
      return errorResponse(403, 'FORBIDDEN');
    }

    const body = JSON.parse(event.body || '{}');
    const { repairId, location, content, contractorName, contractorApproval } = body;

    if (!repairId || !location || !content) {
      return errorResponse(400, 'Missing required fields: repairId, location, content');
    }

    const inspectionId = randomUUID();
    const now = new Date().toISOString();

    const item = {
      pk: `INSPECTION#${inspectionId}`,
      sk: 'DATA',
      id: inspectionId,
      repairId,
      location,
      content,
      contractorName,
      contractorApproval: contractorApproval || false,
      inspectionDate: now,
      createdAt: now,
      updatedAt: now,
      createdBy: auth.userId,
    };

    await docClient.send(
      new PutCommand({
        TableName: TABLE_NAME,
        Item: item,
      })
    );

    await createAuditLog(auth.userId, 'CREATE_INSPECTION', { inspectionId, repairId });

    return response(201, item);
  } catch (error: any) {
    if (error.message === 'UNAUTHORIZED') {
      return errorResponse(401, 'UNAUTHORIZED');
    }
    if (error.message === 'FORBIDDEN') {
      return errorResponse(403, 'FORBIDDEN');
    }
    console.error('Error:', error);
    return errorResponse(500, 'Internal Server Error');
  }
};

// ============================================================================
// GET /inspections/{inspectionId} - 立会い記録詳細取得
// ============================================================================
export const getInspection: APIGatewayProxyHandler = async (event) => {
  try {
    const auth = await getAuthContext(event);
    const inspectionId = event.pathParameters?.inspectionId;

    if (!inspectionId || !validateUUID(inspectionId)) {
      return errorResponse(400, 'Invalid inspection ID');
    }

    const result = await docClient.send(
      new GetCommand({
        TableName: TABLE_NAME,
        Key: { pk: `INSPECTION#${inspectionId}`, sk: 'DATA' },
      })
    );

    if (!result.Item) {
      return errorResponse(404, 'Inspection not found');
    }

    return response(200, result.Item);
  } catch (error: any) {
    if (error.message === 'UNAUTHORIZED') {
      return errorResponse(401, 'UNAUTHORIZED');
    }
    console.error('Error:', error);
    return errorResponse(500, 'Internal Server Error');
  }
};

// ============================================================================
// POST /completion-records - 工事完了記録作成
// ============================================================================
export const createCompletionRecord: APIGatewayProxyHandler = async (event) => {
  try {
    const auth = await getAuthContext(event);

    if (!checkPermission(auth.role, '工事完了記録作成')) {
      return errorResponse(403, 'FORBIDDEN');
    }

    const body = JSON.parse(event.body || '{}');
    const { repairId, report, actualAmount, additionalWork, additionalWorkContent } = body;

    if (!repairId || !report) {
      return errorResponse(400, 'Missing required fields: repairId, report');
    }

    const recordId = randomUUID();
    const now = new Date().toISOString();

    const item = {
      pk: `COMPLETION#${recordId}`,
      sk: 'DATA',
      id: recordId,
      repairId,
      report,
      actualAmount: actualAmount || 0,
      additionalWork: additionalWork || false,
      additionalWorkContent,
      completionStatus: '完了',
      inspectionCompleted: false,
      completionDate: now,
      createdAt: now,
      updatedAt: now,
      createdBy: auth.userId,
    };

    await docClient.send(
      new PutCommand({
        TableName: TABLE_NAME,
        Item: item,
      })
    );

    // Update repair status
    await docClient.send(
      new UpdateCommand({
        TableName: TABLE_NAME,
        Key: { pk: `REPAIR#${repairId}`, sk: 'DATA' },
        UpdateExpression: 'SET #status = :status, updatedAt = :updatedAt',
        ExpressionAttributeNames: { '#status': 'status' },
        ExpressionAttributeValues: {
          ':status': '完了',
          ':updatedAt': now,
        },
      })
    );

    await createAuditLog(auth.userId, 'CREATE_COMPLETION_RECORD', { recordId, repairId });

    return response(201, item);
  } catch (error: any) {
    if (error.message === 'UNAUTHORIZED') {
      return errorResponse(401, 'UNAUTHORIZED');
    }
    if (error.message === 'FORBIDDEN') {
      return errorResponse(403, 'FORBIDDEN');
    }
    console.error('Error:', error);
    return errorResponse(500, 'Internal Server Error');
  }
};

// ============================================================================
// GET /completion-records/{recordId} - 工事完了記録詳細取得
// ============================================================================
export const getCompletionRecord: APIGatewayProxyHandler = async (event) => {
  try {
    const auth = await getAuthContext(event);
    const recordId = event.pathParameters?.recordId;

    if (!recordId || !validateUUID(recordId)) {
      return errorResponse(400, 'Invalid record ID');
    }

    const result = await docClient.send(
      new GetCommand({
        TableName: TABLE_NAME,
        Key: { pk: `COMPLETION#${recordId}`, sk: 'DATA' },
      })
    );

    if (!result.Item) {
      return errorResponse(404, 'Completion record not found');
    }

    return response(200, result.Item);
  } catch (error: any) {
    if (error.message === 'UNAUTHORIZED') {
      return errorResponse(401, 'UNAUTHORIZED');
    }
    console.error('Error:', error);
    return errorResponse(500, 'Internal Server Error');
  }
};

// ============================================================================
// POST /photos - 施工写真アップロード
// ============================================================================
export const uploadPhoto: APIGatewayProxyHandler = async (event) => {
  try {
    const auth = await getAuthContext(event);

    if (!checkPermission(auth.role, '施工写真アップロード')) {
      return errorResponse(403, 'FORBIDDEN');
    }

    const body = JSON.parse(event.body || '{}');
    const { repairId, photoType, filePath, description } = body;

    if (!repairId || !photoType || !filePath) {
      return errorResponse(400, 'Missing required fields: repairId, photoType, filePath');
    }

    const photoId = randomUUID();
    const now = new Date().toISOString();

    const item = {
      pk: `PHOTO#${photoId}`,
      sk: 'DATA',
      id: photoId,
      repairId,
      photoType,
      filePath,
      description,
      captureDate: now,
      createdAt: now,
      updatedAt: now,
      createdBy: auth.userId,
    };

    await docClient.send(
      new PutCommand({
        TableName: TABLE_NAME,
        Item: item,
      })
    );

    await createAuditLog(auth.userId, 'UPLOAD_PHOTO', { photoId, repairId });

    return response(201, item);
  } catch (error: any) {
    if (error.message === 'UNAUTHORIZED') {
      return errorResponse(401, 'UNAUTHORIZED');
    }
    if (error.message === 'FORBIDDEN') {
      return errorResponse(403, 'FORBIDDEN');
    }
    console.error('Error:', error);
    return errorResponse(500, 'Internal Server Error');
  }
};

// ============================================================================
// GET /photos/{repairId} - 修繕依頼の施工写真一覧取得
// ============================================================================
export const listPhotos: APIGatewayProxyHandler = async (event) => {
  try {
    const auth = await getAuthContext(event);
    const repairId = event.pathParameters?.repairId;

    if (!repairId || !validateUUID(repairId)) {
      return errorResponse(400, 'Invalid repair ID');
    }

    const result = await docClient.send(
      new ScanCommand({
        TableName: TABLE_NAME,
        FilterExpression: 'begins_with(pk, :pk) AND repairId = :repairId',
        ExpressionAttributeValues: {
          ':pk': 'PHOTO#',
          ':repairId': repairId,
        },
      })
    );

    return response(200, {
      photos: result.Items || [],
      count: result.Count || 0,
    });
  } catch (error: any) {
    if (error.message === 'UNAUTHORIZED') {
      return errorResponse(401, 'UNAUTHORIZED');
    }
    console.error('Error:', error);
    return errorResponse(500, 'Internal Server Error');
  }
};

// ============================================================================
// POST /categories - 修繕カテゴリ作成
// ============================================================================
export const createCategory: APIGatewayProxyHandler = async (event) => {
  try {
    const auth = await getAuthContext(event);

    if (auth.role !== 'admin') {
      return errorResponse(403, 'FORBIDDEN: Only admin can create categories');
    }

    const body = JSON.parse(event.body || '{}');
    const { name, description, displayOrder } = body;

    if (!name || displayOrder === undefined) {
      return errorResponse(400, 'Missing required fields: name, displayOrder');
    }

    const categoryId = randomUUID();
    const now = new Date().toISOString();

    const item = {
      pk: `CATEGORY#${categoryId}`,
      sk: 'DATA',
      id: categoryId,
      name,
      description,
      displayOrder,
      isActive: true,
      createdAt: now,
      updatedAt: now,
      createdBy: auth.userId,
    };

    await docClient.send(
      new PutCommand({
        TableName: TABLE_NAME,
        Item: item,
      })
    );

    await createAuditLog(auth.userId, 'CREATE_CATEGORY', { categoryId, name });

    return response(201, item);
  } catch (error: any) {
    if (error.message === 'UNAUTHORIZED') {
      return errorResponse(401, 'UNAUTHORIZED');
    }
    if (error.message === 'FORBIDDEN') {
      return errorResponse(403, 'FORBIDDEN');
    }
    console.error('Error:', error);
    return errorResponse(500, 'Internal Server Error');
  }
};

// ============================================================================
// GET /categories - 修繕カテゴリ一覧取得
// ============================================================================
export const listCategories: APIGatewayProxyHandler = async (event) => {
  try {
    const auth = await getAuthContext(event);

    const result = await docClient.send(
      new QueryCommand({
        TableName: TABLE_NAME,
        KeyConditionExpression: 'begins_with(pk, :pk)',
        ExpressionAttributeValues: { ':pk': 'CATEGORY#' },
      })
    );

    const categories = (result.Items || []).sort((a, b) => (a.displayOrder || 0) - (b.displayOrder || 0));

    return response(200, {
      categories,
      count: result.Count || 0,
    });
  } catch (error: any) {
    if (error.message === 'UNAUTHORIZED') {
      return errorResponse(401, 'UNAUTHORIZED');
    }
    console.error('Error:', error);
    return errorResponse(500, 'Internal Server Error');
  }
};

// ============================================================================
// GET /audit-logs - 監査ログ取得
// ============================================================================
export const getAuditLogs: APIGatewayProxyHandler = async (event) => {
  try {
    const auth = await getAuthContext(event);

    if (auth.role !== 'admin') {
      return errorResponse(403, 'FORBIDDEN: Only admin can view audit logs');
    }

    const result = await docClient.send(
      new QueryCommand({
        TableName: TABLE_NAME,
        KeyConditionExpression: 'pk = :pk',
        ExpressionAttributeValues: { ':pk': 'AUDIT' },
        ScanIndexForward: false,
        Limit: 100,
      })
    );

    return response(200, {
      logs: result.Items || [],
      count: result.Count || 0,
    });
  } catch (error: any) {
    if (error.message === 'UNAUTHORIZED') {
      return errorResponse(401, 'UNAUTHORIZED');
    }
    if (error.message === 'FORBIDDEN') {
      return errorResponse(403, 'FORBIDDEN');
    }
    console.error('Error:', error);
    return errorResponse(500, 'Internal Server Error');
  }
};
import { DynamoDBClient } from '@aws-sdk/client-dynamodb';
import { DynamoDBDocumentClient, GetCommand } from '@aws-sdk/lib-dynamodb';

export type Role = 'admin' | 'operator' | 'viewer';

export interface Permission {
  修繕依頼作成: boolean;
  修繕依頼編集: boolean;
  修繕依頼削除: boolean;
  見積書承認: boolean;
  進捗更新: boolean;
  立会い記録作成: boolean;
  施工写真アップロード: boolean;
  工事完了記録作成: boolean;
  レポート閲覧: boolean;
}

const rolePermissions: Record<Role, Permission> = {
  admin: {
    修繕依頼作成: true,
    修繕依頼編集: true,
    修繕依頼削除: true,
    見積書承認: true,
    進捗更新: true,
    立会い記録作成: true,
    施工写真アップロード: true,
    工事完了記録作成: true,
    レポート閲覧: true,
  },
  operator: {
    修繕依頼作成: true,
    修繕依頼編集: true,
    修繕依頼削除: false,
    見積書承認: true,
    進捗更新: true,
    立会い記録作成: true,
    施工写真アップロード: true,
    工事完了記録作成: true,
    レポート閲覧: true,
  },
  viewer: {
    修繕依頼作成: false,
    修繕依頼編集: false,
    修繕依頼削除: false,
    見積書承認: false,
    進捗更新: false,
    立会い記録作成: false,
    施工写真アップロード: false,
    工事完了記録作成: false,
    レポート閲覧: true,
  },
};

export async function getUserRole(userId: string, docClient: DynamoDBDocumentClient): Promise<Role> {
  try {
    const result = await docClient.send(
      new GetCommand({
        TableName: process.env.MAIN_TABLE!,
        Key: { pk: `USER#${userId}`, sk: 'PROFILE' },
      })
    );
    return (result.Item?.role as Role) || 'viewer';
  } catch {
    return 'viewer';
  }
}

export function checkPermission(role: Role, action: keyof Permission): boolean {
  return rolePermissions[role][action];
}

export function requirePermission(role: Role, action: keyof Permission): void {
  if (!checkPermission(role, action)) {
    throw new Error(`FORBIDDEN: ${action}`);
  }
}

export function isBulkAllowed(role: Role): boolean {
  return role === 'admin' || role === 'operator';
}
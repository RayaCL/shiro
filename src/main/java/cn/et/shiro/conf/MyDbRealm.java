package cn.et.shiro.conf;

import java.util.Set;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAccount;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import cn.et.shiro.dao.UserMapper;
import cn.et.shiro.entity.UserInfo;
@Component
public class MyDbRealm extends AuthorizingRealm {
	@Autowired
	UserMapper userMapper;
	/**
	 * ��֤
	 * ����½������û�������������ݿ��е��û���������Ա�  �Ƿ����
	 * ����ֵnull��ʾ��֤ʧ�� ��null��֤ͨ��
	 */
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		//��ȡ��ҳ�洫���token 
		UsernamePasswordToken upt=(UsernamePasswordToken)token;
		//�����ݿ��в�ѯuserinfo����
		UserInfo queryUser=userMapper.queryUser(upt.getUsername());
		//�������Ϊ��,��������� ���Ե�¼
		if(queryUser!=null && queryUser.getPassword().equals(new String(upt.getPassword()))){
			SimpleAccount sa=new SimpleAccount(upt.getUsername(),upt.getPassword(),"MyDbRealm");
			return sa;
		}
		return null;
	}
	/**
	 * ��ȡ��ǰ�ļ�����Ȩ����
	 * ����ǰ�û������ݿ�Ľ�ɫ��Ȩ�� ���ص�AuthorizationInfo
	 * Ĭ���ڽ�����Ȩ��֤�ĵ��� ���Ȩ�޵���checkRole checkPerm
	 */
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		//��ȡ�û���
		String userName=principals.getPrimaryPrincipal().toString();
		//��ȡ��ɫ
		Set<String> roleList=userMapper.queryRoleByName(userName);
		//��ȡȨ��
		Set<String> permsList=userMapper.queryPermsByName(userName);
		SimpleAuthorizationInfo sa=new SimpleAuthorizationInfo();
		sa.setRoles(roleList);
		sa.setStringPermissions(permsList);
		return sa;
	}

	
	
	
	
	
	
	
	

}

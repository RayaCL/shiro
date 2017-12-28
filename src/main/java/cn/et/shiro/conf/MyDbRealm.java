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
	 * 认证
	 * 将登陆输入的用户名和密码和数据库中的用户名和密码对比  是否相等
	 * 返回值null表示认证失败 非null认证通过
	 */
	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
		//获取从页面传入的token 
		UsernamePasswordToken upt=(UsernamePasswordToken)token;
		//从数据库中查询userinfo对象
		UserInfo queryUser=userMapper.queryUser(upt.getUsername());
		//如果对象不为空,且密码相等 可以登录
		if(queryUser!=null && queryUser.getPassword().equals(new String(upt.getPassword()))){
			SimpleAccount sa=new SimpleAccount(upt.getUsername(),upt.getPassword(),"MyDbRealm");
			return sa;
		}
		return null;
	}
	/**
	 * 获取当前文件的授权数据
	 * 将当前用户在数据库的角色和权限 加载到AuthorizationInfo
	 * 默认在进行授权认证的调用 检查权限调用checkRole checkPerm
	 */
	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principals) {
		//获取用户名
		String userName=principals.getPrimaryPrincipal().toString();
		//获取角色
		Set<String> roleList=userMapper.queryRoleByName(userName);
		//获取权限
		Set<String> permsList=userMapper.queryPermsByName(userName);
		SimpleAuthorizationInfo sa=new SimpleAuthorizationInfo();
		sa.setRoles(roleList);
		sa.setStringPermissions(permsList);
		return sa;
	}

	
	
	
	
	
	
	
	

}

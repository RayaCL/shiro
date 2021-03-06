package cn.et.shiro.controller;

import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.UnknownAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;

import cn.et.shiro.dao.UserMapper;

@Controller
public class SpringLoginController {
	@Autowired
	UserMapper userMapper;
	@RequestMapping("loginShiro")
	public String login(String userName,String password,Model model){
	
		//获取当前用户
		Subject currentUser = SecurityUtils.getSubject();
		UsernamePasswordToken token = new UsernamePasswordToken(userName, password);
		try{
		currentUser.login(token);
		//查询菜单
		model.addAttribute("menuList", userMapper.queryMenuByUser(userName));
		return "/layout.jsp";
		} catch ( UnknownAccountException uae ) {
		    System.out.println("账号错误");
		} catch ( IncorrectCredentialsException ice ) {
		    System.out.println("密码不匹配");
		} catch ( LockedAccountException lae ) {
		   System.out.println("账号被锁定");
		} catch ( AuthenticationException ae ) {
		    System.out.println("位置异常");
		}
		return "ennr.jsp";
	}
}

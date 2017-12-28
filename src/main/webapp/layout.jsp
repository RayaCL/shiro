<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<%@taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@page pageEncoding="UTF-8" %>
<html>
  <head>
    <title>layout.html</title>
	
    <meta http-equiv="keywords" content="keyword1,keyword2,keyword3">
    <meta http-equiv="description" content="this is my page">
    <meta http-equiv="content-type" content="text/html; charset=UTF-8">
    
    <!--<link rel="stylesheet" type="text/css" href="./styles.css">-->
	<link rel="stylesheet" type="text/css" href="themes/default/easyui.css">
	<link rel="stylesheet" type="text/css" href="themes/icon.css">
	<script type="text/javascript" src="jquery.min.js"></script>
	<script type="text/javascript" src="jquery.easyui.min.js"></script>
	<script type="text/javascript">
	function urlClick(myTitle,myUrl){
			//判断title='学生管理'tab页是否存在
			var ifExist=$("#myTabs").tabs("exists",myTitle);
			if(!ifExist){
				$("#myTabs").tabs("add",{
					title:myTitle,
					closable:true,
					content:'<iframe frameborder=0 width="100%" height="100%" scrolling="no" src="'+myUrl+'"></iframe>'
				})
			}
			$("#myTabs").tabs("select",myTitle);
		}
	</script>
  </head>
  
  <body style="padding:1px;margin:1px">
    <div class="easyui-layout" style="width:100%;height:100%;">
		<!-- 北部 只能设置高度  一般不会设置宽度 -->
		<div data-options="region:'north'" style="height:15%">
			<div style="height:85%;text-align: center;">
				<img alt="" src="timg.jpg"   style="margin:0 auto;width:700px;height:130px">
			</div>
			<div style="text-align:right;width:90%"><a href="">退出</a></div>
		</div>
		<!-- split:true添加分割条,可移动的 -->
		<div data-options="region:'west',split:true" title="West" style="width:18% ;">
			<div class="easyui-accordion" style="width:500px;height:300px;">
				<div  title="权限管理" style="overflow:auto;padding:10px;">
					<c:forEach var="v" items="${requestScope.menuList }">
					<a  href="javascript:urlClick('${v.menuName }','${pageContext.request.contextPath}${v.menuUrl}')" style="text-decoration:none"><img alt="" src="themes/icons/tip.png" style="margin-top:10px">${v.menuName}</a><br/>
					</c:forEach>
				</div>
				<div title="系统设置" style="padding:10px;">
					
				</div>
			</div>
		</div>
		<div data-options="region:'center',title:'Main Title',iconCls:'icon-ok'">
			<div id="myTabs" class="easyui-tabs" style="width:100%;height:100%">
				<div  title="欢迎使用" style="padding:10px" ></div>
				
			</div>
		</div>
	</div>
  </body>
</html>

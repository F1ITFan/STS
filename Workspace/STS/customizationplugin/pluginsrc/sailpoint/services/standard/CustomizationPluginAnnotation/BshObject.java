package sailpoint.services.standard.CustomizationPluginAnnotation;

import java.io.FileNotFoundException;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.lang.reflect.Parameter;
import java.util.ArrayList;
import java.util.List;

import org.apache.log4j.Logger;

import sailpoint.services.standard.CustomizationPluginAnnotation.Rule;
import sailpoint.services.standard.CustomizationPluginAnnotation.RuleLibrary;
import sailpoint.services.standard.CustomizationPluginAnnotation.RuleLibraryMethod;
import sailpoint.tools.GeneralException;

public class BshObject {
	
	private static Logger log = Logger.getLogger(BshObject.class);
	
	private static String XML_OBJECT_NAME = "%%XML_OBJECT_NAME%%";
	private static String XML_OBJECT_BODY = "%%XML_OBJECT_BODY%%"; 
	private static String XML_OBJECT_TYPE_PLACEHOLDER = "%%XML_OBJECT_TYPE_PLACEHOLDER%%"; 
	private static String XML_OBJECT = "<?xml version='1.0' encoding='UTF-8'?>\n" + 
			"<!DOCTYPE Rule PUBLIC \"sailpoint.dtd\" \"sailpoint.dtd\">\n" + 
			"<Rule   language=\"beanshell\" name=\"%%XML_OBJECT_NAME%%\" %%XML_OBJECT_TYPE_PLACEHOLDER%% >\n" + 
			"\t<Source>\n" + 
			"\t<![CDATA["
			+"%%XML_OBJECT_BODY%%"
			+ "\t]]>\n" + 
			"\t</Source>\n" + 
			"</Rule>"
			;
	
	private static String BSH_CODE_CLASS_NAME = "%%BSH_CODE_CLASS_NAME%%";
	private static String BSH_CODE_METHOD_NAME = "%%BSH_CODE_METHOD_NAME%%";
	private static String BSH_CODE_METHOD_ARG_TYPES = "%%BSH_CODE_METHOD_ARG_TYPES%%";
	private static String BSH_CODE_METHOD_ARG_NAMES = "%%BSH_CODE_METHOD_ARG_NAMES%%";
	private static String BSH_CODE_METHOD_RETURN_STMT = "%%BSH_CODE_METHOD_RETURN_STMT%%";
	private static String BSH_CODE_PLUGIN_NAME = "%%BSH_CODE_PLUGIN_NAME%%";
	 
	private static String BSH_CODE_BODY =  
			"\n" + 
			"\tClassLoader clsLoader = sailpoint.server.Environment.getEnvironment().getPluginsCache().getClassLoader(\"%%BSH_CODE_PLUGIN_NAME%%\");\n" + 
			"\n" + 
			"\ttry\n" + 
			"\t{\n" + 
			"\t\tClass clObj = clsLoader.loadClass(\"%%BSH_CODE_CLASS_NAME%%\");\n" + 
			"\t\tjava.lang.reflect.Method mToCall =  clObj.getMethod(\"%%BSH_CODE_METHOD_NAME%%\"%%BSH_CODE_METHOD_ARG_TYPES%%);\n" + 
			"\t\t%%BSH_CODE_METHOD_RETURN_STMT%%mToCall.invoke(null%%BSH_CODE_METHOD_ARG_NAMES%%);\n" + 
			"\n" + 
			"\n" + 
			"\t}\n" + 
			"\tcatch(Exception e)\n" + 
			"\t{\n" + 
			"\t\tlog.error(\"%%BSH_CODE_METHOD_NAME%% call error\",e);\n" + 
			"\t\tthrow e;\n" + 
			"\t}"; 
	
	private String bodyCode="";
	private String name="";
	private String type="";
	
	private String getBshMethodCode(Class<?> clsObj,Method mObj,boolean isMethod,String pluginName) {
		String returnType = null;
		String paramTypes = "";
		String paramNames = "";
		String paramDeclaration = null;
		
		log.debug("Method ["+mObj.getName()+"] from class ["+clsObj.getName()+"] has rule library method annotation");
		
		log.debug("Return:" + mObj.getReturnType());
		returnType = mObj.getReturnType().getName();
		
		if(returnType!=null)
			log.info("Return Type:"+returnType);
		
		
		Parameter[] paramsObjs =  mObj.getParameters();
		if(paramsObjs!=null && paramsObjs.length>0)
			for(int i=0;i<paramsObjs.length;i++)
			{
				//log.debug(paramsObjs[i]);
				
				String paramName = paramsObjs[i].getName();
				
				Annotation annotation = paramsObjs[i].getAnnotation(RuleArgument.class);
				if(annotation!=null)
				{
					RuleArgument argInfo = (RuleArgument) annotation;
					if(argInfo.name()!=null && !argInfo.name().isEmpty())
						paramName = argInfo.name();
				}
				
				paramTypes+="," + paramsObjs[i].getType().getName() + ".class";

				paramNames+="," + paramName;
				
				if(paramDeclaration==null|| paramDeclaration.isEmpty())
					paramDeclaration=paramsObjs[i].getType().getName() + " " + paramName ;
				else
					paramDeclaration+="," + paramsObjs[i].getType().getName() + " " + paramName;
			}
		
		
		
		String outCode = "";
		if(isMethod)
		{
			outCode += "public " + returnType+" " + mObj.getName() + "(";
			if(paramDeclaration!=null)
				outCode+=paramDeclaration;
			outCode+=") {";
		}
		
		String body = BSH_CODE_BODY;
		body=body.replaceAll(BSH_CODE_CLASS_NAME, clsObj.getName());
		body=body.replaceAll(BSH_CODE_METHOD_NAME, mObj.getName());
		body=body.replaceAll(BSH_CODE_METHOD_ARG_NAMES, paramNames);
		body=body.replaceAll(BSH_CODE_METHOD_ARG_TYPES, paramTypes);
		body=body.replaceAll(BSH_CODE_PLUGIN_NAME, pluginName);
		if(returnType.equals("void"))
			body=body.replaceAll(BSH_CODE_METHOD_RETURN_STMT, "");
		else
			body=body.replaceAll(BSH_CODE_METHOD_RETURN_STMT, "return ");
		
		outCode+=body;
		
		if(isMethod)
		{
			outCode+="\n}\n";
		}
		
		return outCode;
	}

	
	private  void transformToRuleLibrary(Class<?> clsObj,String pluginName)
	{
		Annotation annotation = clsObj.getAnnotation(RuleLibrary.class);
		RuleLibrary ruleLibraryInfo = (RuleLibrary) annotation;
		String ruleLibraryName = ruleLibraryInfo.name();
		log.info("Processing ["+clsObj.getName()+"]");
		log.info("ruleLibraryName:"+ruleLibraryName);
		name = ruleLibraryName;
		
		//bodyCode = "class " + name + "{";
		
		if(clsObj.getDeclaredMethods()!=null)
			for(Method mObj : clsObj.getDeclaredMethods())
			{
				
				if(mObj.isAnnotationPresent(RuleLibraryMethod.class))
				{
					String libMethodBody = getBshMethodCode(clsObj,mObj,true,pluginName);
					log.trace(libMethodBody);
					bodyCode += libMethodBody + "\n";
				}
			}
		//bodyCode += "}";
	}
	
	
	private  void transformToRule(Class<?> clsObj, Method mObj,String pluginName)
	{
		Annotation annotation = mObj.getAnnotation(Rule.class);
		Rule ruleInfo = (Rule) annotation;
		String ruleName = ruleInfo.name();
		log.info("Processing ["+clsObj.getName()+"]");
		log.info("ruleName:"+ruleName);
		name = ruleName;
		if(ruleInfo.type()!=null && !ruleInfo.type().isEmpty())
			type = ruleInfo.type();

		String libMethodBody = getBshMethodCode(clsObj,mObj,false,pluginName);
		log.trace(libMethodBody);
		bodyCode += libMethodBody + "\n";

	}
	
	
	public static BshObject getRuleLibrary(Class<?> clsObj,String pluginName)
	{
		BshObject b = new BshObject();
		b.transformToRuleLibrary(clsObj,pluginName);
		return b;
		
	}
	
	public static BshObject getRule(Class<?> clsObj,Method mObj,String pluginName)
	{
		BshObject b = new BshObject();
		b.transformToRule(clsObj,mObj,pluginName);
		return b;
		
	}
	
	public String getRuleCode() throws GeneralException
	{
		String objTxt = XML_OBJECT;
		objTxt=objTxt.replaceAll(XML_OBJECT_NAME, name).replaceAll(XML_OBJECT_BODY, bodyCode);
		if(type!=null && !type.isEmpty())
			objTxt=objTxt.replaceAll(XML_OBJECT_TYPE_PLACEHOLDER, " type=\""+type+"\" ");
		else
			objTxt=objTxt.replaceAll(XML_OBJECT_TYPE_PLACEHOLDER, "");
		
		return objTxt;
	}
	
	
	public void saveToDirectory(String outputDir) throws FileNotFoundException, UnsupportedEncodingException, GeneralException
	{
		
		PrintWriter writer = new PrintWriter(outputDir+"/"+name+".xml", "UTF-8");
		writer.println(getRuleCode());
		writer.close();
		
	}

}

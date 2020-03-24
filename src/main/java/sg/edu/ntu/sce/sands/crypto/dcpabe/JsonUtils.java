package sg.edu.ntu.sce.sands.crypto.dcpabe;


import com.alibaba.fastjson.JSON;
import com.alibaba.fastjson.TypeReference;

import java.util.List;
import java.util.Map;

public class JsonUtils {
    private JsonUtils() {

    }

    public static String toJson(Object clazz) {
        return JSON.toJSONString(clazz);
    }

    public static <T> T parseJson(String content, Class<T> clazz) {
        return JSON.parseObject(content, clazz);
    }

    public static Map<String, Object> parse2Map(String json) {
        return JSON.parseObject(json, new TypeReference<Map<String, Object>>() {
        });
    }

    public static List<Object> parse2List(String json) {
        return JSON.parseObject(json, new TypeReference<List<Object>>() {
        });
    }
}
